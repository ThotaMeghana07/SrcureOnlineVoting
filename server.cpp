#include "imports.hh"
using namespace std;

int PollCount = 1;
struct User
{
    string email;
    string password;
    int fd;
    RSA *clientRSA;
};
map<string, User> users;

struct Poll
{
    int id;
    string poll_by;
    string Qn_optns;
    map<string, int> poll_status;
};
vector<Poll> polls;

RSA *serverRSA;
const BIGNUM *sn = NULL, *se = NULL, *sd = NULL;

bool signup(string email, string password, int nsfd, RSA *rsa)
{
    srand(time(0));
    string otp = "";
    for (int i = 0; i < 8; ++i)
    {
        otp.push_back('0' + (rand() % 10));
    }

    string response = mailSender(email, otp);
    if (response.substr(0, 5) != "Check")
        response = "error";

    response = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(response.c_str()), response.size(), rsa);
    if (send(nsfd, response.c_str(), response.size(), 0) < 0)
        pthread_exit(NULL);

    char buffer[6000] = {'\0'};
    int valread = recv(nsfd, buffer, 6000, 0);
    string recvdOTP = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(buffer), valread, serverRSA);
    if (recvdOTP == otp)
    {
        users[email] = {email, password, -1, rsa};
        return 1;
    }
    return 0;
}

bool signin(string email, string password)
{
    auto it = users.find(email);
    if (it != users.end() && it->second.password == password)
    {
        cout << "password recieved : " << password << endl;
        cout << "Actual password : " << it->second.password << endl;
        return true;
    }
    return false;
}

bool CheckPollStatus(struct Poll x)
{
    for (auto i : x.poll_status)
    {
        cout << i.first << " " << i.second << endl;
        if (i.second == -1)
            return false;
    }
    return true;
}

void PostPoll(int sfd, string email)
{
    char buffer[6000] = {'\0'};
    int valread = recv(sfd, buffer, 6000, 0);
    string PollQn = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(buffer), valread, serverRSA);
    ;
    cout << "Received poll question: " << PollQn << endl;
    map<string, int> poll_status;
    polls.push_back({PollCount++, email, PollQn, poll_status});
}

int GetWinningOption(map<string, int> votes)
{
    vector<int> count(4, 0);
    for (auto it : votes)
    {
        count[it.second - 1]++;
        cout << it.second << " ";
    }
    int index = max_element(count.begin(), count.end()) - count.begin();
    return index + 1;
}

void SendPoll(int nsfd, string email, RSA *rsa)
{
    string UnansweredPolls;
    for (auto each_poll : polls)
    {
        if (each_poll.poll_by != email && each_poll.poll_status[email] == 0)
        {
            string qn;
            istringstream iss(each_poll.Qn_optns);
            getline(iss, qn, ':');
            UnansweredPolls += (to_string(each_poll.id) + ")" + qn + ":");
        }
    }
    send(nsfd, UnansweredPolls.c_str(), UnansweredPolls.length(), 0);
    while (1)
    {
        char buff[2000] = {'\0'};
        recv(nsfd, buff, sizeof(buff), 0);
        string qid(buff);
        if (qid == "-1")
            break;
        for (auto &each_poll : polls)
        {
            if (each_poll.id == stoi(qid) && each_poll.poll_status[email] == 0)
            {
                send(nsfd, each_poll.Qn_optns.c_str(), each_poll.Qn_optns.length(), 0);

                char optbuff[2000] = {'\0'};
                int bytes_read = recv(nsfd, optbuff, sizeof(optbuff), 0);
                string option = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(optbuff), bytes_read, serverRSA);
                cout << "option recieved : " << option << endl;

                char optbuff2[2000] = {'\0'};
                bytes_read = recv(nsfd, optbuff2, sizeof(optbuff2), 0);
                string Hash = rsaPublicDecrypt(reinterpret_cast<const unsigned char *>(optbuff2), bytes_read, rsa);

                // compare recieved hash and calculated hash
                cout << "calculated Hash : " << hashSHA256(option) << endl;
                cout << "recieved Hash : " << Hash << endl;
                if (Hash == hashSHA256(option))
                    cout << "Digital Signature Successfully Verified" << endl;

                each_poll.poll_status[email] = stoi(option);
                cout << each_poll.poll_status[email] << endl;
            }
        }
    }
}

void SendResults(int nsfd, string email, RSA *rsa)
{
    string Result;
    for (auto each_poll : polls)
    {

        if (each_poll.poll_by == email)
        {
            int opt = GetWinningOption(each_poll.poll_status);
            string PollQn = each_poll.Qn_optns;
            size_t pos = PollQn.find(':');
            string question = PollQn.substr(0, pos);
            string options = PollQn.substr(pos + 1);
            istringstream iss(options);
            string option1, option2, option3, option4;
            getline(iss, option1, ':');
            getline(iss, option2, ':');
            getline(iss, option3, ':');
            getline(iss, option4, ':');

            cout << question << " " << email << " " << opt << endl;
            cout << Result << endl;
            if (opt == 1)
                Result += (question + " - " + option1 + ":");
            else if (opt == 2)
                Result += (question + " - " + option2 + ":");
            else if (opt == 3)
                Result += (question + " - " + option3 + ":");
            else if (opt == 4)
                Result += (question + " - " + option4 + ":");
            cout << Result << endl;
        }
    }
    Result = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(Result.c_str()), Result.size(), rsa);
    send(nsfd, Result.c_str(), Result.length(), 0);
}

void *clientHandler(void *args)
{
    int nsfd = *((int *)args);
    char buffer[1024] = {0};
    string response;

    // key exchanging
    char *pubN = printHex(sn, "Public key (n)");
    char *pubE = printHex(se, "Public key (e)");
    char user_n[6000] = {'\0'};
    recv(nsfd, user_n, sizeof(user_n), 0);
    sleep(1);
    send(nsfd, pubN, strlen(pubN) + 1, 0);
    sleep(1);

    char user_e[6000] = {'\0'};
    recv(nsfd, user_e, sizeof(user_e), 0);
    sleep(1);
    send(nsfd, pubE, strlen(pubE) + 1, 0);
    sleep(1);
    cout << "Key exchange successful" << endl;

    RSA *rsa = setRSAAttributes(user_n, user_e);

    // Read (Decrypt)client request
    int bytes_read = read(nsfd, buffer, 1024);
    string request = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(buffer), bytes_read, serverRSA);
    cout << "request : " << request << endl;

    int pos = request.find(':');
    string command = request.substr(0, pos);
    string data = request.substr(pos + 1);
    pos = data.find(':');
    string email = data.substr(0, pos);
    string password = data.substr(pos + 1);

//Process Auth req
    bool res;
    if (command == "signup")
    {
        res = signup(email, password, nsfd, rsa);
        response = res ? "signup successful" : "Invalid otp";
        if (res)
            cout << "User signed-up " << email << " pswd : " << password << endl;
    }
    else if (command == "signin")
    {
        cout << "signin request from " << email << endl;
        res = signin(email, password);
        response = res ? "signin successful" : "Invalid email or password";
        if (response == "signin successful")
        {
            cout << "User signed-in " << email << " pswd : " << password << endl;
        }
    }
    else
    {
        response = "Invalid command";
    }
//encrypt and sends respond 
    response = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(response.c_str()), response.size(), rsa);
    send(nsfd, response.c_str(), response.size(), 0);

    if (res)
    {
        users[email].fd = nsfd;
        users[email].clientRSA = rsa;
    }
    else
        pthread_exit(NULL);

    while (1)
    {
        char command_buffer[1024] = {'\0'};
        recv(nsfd, command_buffer, 6000, 0);
        string command(command_buffer);
        if (command == "logout")
        {
            users[email].fd = -1;
            close(nsfd);
            break;
        }
        else if (command == "PostPoll")
        {
            string response = "granted";
            send(nsfd, response.c_str(), response.size(), 0);
            PostPoll(nsfd, email);
        }
        else if (command == "AnswerPoll")
        {
            SendPoll(nsfd, email, rsa);
        }
        else if (command == "ShowResults")
        {
            SendResults(nsfd, email, rsa);
        }
    }

    return NULL;
}

int main()
{
    int sfd = Create_TCPSocket_server();
    serverRSA = generateRSAKeyPair(1024);
    RSA_get0_key(serverRSA, &sn, &se, &sd);
    cout<<"My key pairs : "<<endl<<sn<<endl<<se<<endl<<sd<<endl;

    while (true)
    {
        sockaddr_in address;
        int addrlen = sizeof(address);
        int nsfd = accept(sfd, (struct sockaddr *)&address, (socklen_t *)&addrlen);
        pthread_t th;
        pthread_create(&th, NULL, clientHandler, (void *)&nsfd);
    }
    close(sfd);
    return 0;
}