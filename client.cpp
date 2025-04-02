#include "imports.hh"
using namespace std;

RSA *clientRSA, *serverRSA;

void AnswerPoll(int sfd)
{
    char buffer[1024];
    read(sfd, buffer, 1024);
    string PollQn(buffer);
    if (PollQn[0] == '#')
    {
        cout << "no questions to answer!!" << endl;
        return;
    }

    size_t pos = PollQn.find(':');
    string question = PollQn.substr(0, pos);
    string options = PollQn.substr(pos + 1);
    istringstream iss(options);
    string option1, option2, option3, option4;
    getline(iss, option1, ':');
    getline(iss, option2, ':');
    getline(iss, option3, ':');
    getline(iss, option4, ':');

    cout << "Please answer the following poll" << endl;
    cout << question << endl;
    cout << "The options are " << endl;
    cout << "1:" << option1 << endl;
    cout << "2:" << option2 << endl;
    cout << "3:" << option3 << endl;
    cout << "4:" << option4 << endl;
    cout << "enter your option 1 or 2 or 3 or 4" << endl;
    string option;
    cin >> option;

    string HashofOption = hashSHA256(option);

    option = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(option.c_str()), option.size(), serverRSA);
    send(sfd, option.c_str(), size(option), 0);
    sleep(1);

    HashofOption = rsaPrivateEncrypt(reinterpret_cast<const unsigned char *>(HashofOption.c_str()), HashofOption.size(), clientRSA);
    send(sfd, HashofOption.c_str(), size(HashofOption), 0);
}

void PostPoll(int sfd)
{
    string question, option1, option2, option3, option4;

    cout << "Enter the poll question: ";
    cin.ignore();
    getline(cin, question);
    cout << "Enter the options one by one" << endl;
    cout << "Option 1: ";
    getline(cin, option1);
    cout << "Option 2: ";
    getline(cin, option2);
    cout << "Option 3: ";
    getline(cin, option3);
    cout << "Option 4: ";
    getline(cin, option4);

    string PollQn = question + ":" + option1 + ":" + option2 + ":" + option3 + ":" + option4 + ":";
    PollQn = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(PollQn.c_str()), PollQn.size(), serverRSA);
    send(sfd, PollQn.c_str(), PollQn.length(), 0);
    cout << "Poll posted successfully!" << endl;
}

void DisplayResults(int sfd)
{
    char buffer[6000] = {'\0'};
    int valread = recv(sfd, buffer, 6000, 0);
    string results = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(buffer), valread, clientRSA);

    cout << "The Results of all the qns and answers that are posted by you are " << endl;
    istringstream iss(results);
    while (1)
    {
        string x;
        getline(iss, x, ':');
        if (x == "")
            break;
        cout << x << endl;
    }
}

int main()
{
    string command;
    string email, password;
    string message;
    char buffer[6000] = {'\0'};
    int port;
    string ip;

    port = 9000;
    ip = "127.0.0.1";
    int sfd = Create_TCPSocket_client(port, ip);
    clientRSA = generateRSAKeyPair(1024);
    const BIGNUM *cn = NULL, *ce = NULL, *cd = NULL;
    RSA_get0_key(clientRSA, &cn, &ce, &cd);

    // key exchange
    char *pubN = printHex(cn, "Public key (n)");
    char *pubE = printHex(ce, "Public key (e)");
    cout << "pubN : " << pubN << endl
         << "PubE :" << pubE << endl;
    send(sfd, pubN, strlen(pubN) + 1, 0);
    sleep(1);
    char server_n[6000] = {'\0'};
    recv(sfd, server_n, sizeof(server_n), 0);
    sleep(1);

    send(sfd, pubE, strlen(pubE) + 1, 0);
    sleep(1);
    char server_e[6000] = {'\0'};
    recv(sfd, server_e, sizeof(server_e), 0);
    sleep(1);

    serverRSA = setRSAAttributes(server_n, server_e);

    cout << "Enter command (signup/signin/exit): ";
    cin >> command;
    if (command == "signup" || command == "signin")
    {
        cout << "Enter email: ";
        cin >> email;
        cout << "Enter password: ";
        cin >> password;
        string hashed_password = hashSHA256(password);
        cout << "Hashed Password : " << hashed_password << endl;
        message = command + ":" + email + ":" + hashed_password;
        cout << "message : " << message << endl;
        message = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(message.c_str()), message.size(), serverRSA);
        int valread = send(sfd, message.c_str(), message.length(), 0);

        valread = recv(sfd, buffer, 6000, 0);
        buffer[valread] = '\0';
        string serverResponse = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(buffer), valread, clientRSA);

        if (command == "signup")
        {
            cout << "Server response: " << serverResponse << endl;
            if (serverResponse.substr(0, 5) != "Check")
                exit(0);
            cout << "Enter otp : ";
            string otp;
            cin >> otp;
            otp = rsaPublicEncrypt(reinterpret_cast<const unsigned char *>(otp.c_str()), otp.size(), serverRSA);
            send(sfd, otp.c_str(), otp.length(), 0);
            valread = recv(sfd, buffer, 1024, 0);
            buffer[valread] = '\0';
            serverResponse = rsaPrivateDecrypt(reinterpret_cast<const unsigned char *>(buffer), valread, clientRSA);
        }
        cout << "Server response: " << serverResponse << endl;

        if (serverResponse == "Invalid email or password" || serverResponse == "Invalid otp")
            exit(0);

        while (true)
        {
            cout << "Enter command (PostPoll/AnswerPoll/logout/ShowResults): ";
            cin >> command;
            send(sfd, command.c_str(), command.length(), 0);

            if (command == "PostPoll")
            {
                char buffer[6000] = {'\0'};
                recv(sfd, buffer, 6000, 0);
                string permission(buffer);
                cout << "Server Response : " << permission << endl;
                if (permission != "granted")
                    continue;
                PostPoll(sfd);
            }
            else if (command == "AnswerPoll")
            {
                cout << "The Qns that needs to be answered by you are" << endl;
                char buffer[1024] = {0};
                read(sfd, buffer, 1024);
                string qns(buffer);
                istringstream iss(qns);
                while (true)
                {
                    string question;
                    getline(iss, question, ':');
                    if (question == "")
                        break;
                    cout << question << endl;
                }
                while (true)
                {
                    cout << "enter qn id to answer and -1 to break" << endl;
                    string qid;
                    cin >> qid;
                    send(sfd, qid.c_str(), qid.length(), 0);
                    if (qid == "-1")
                        break;
                    AnswerPoll(sfd);
                }
            }
            else if (command == "ShowResults")
            {
                DisplayResults(sfd);
            }
            else if (command == "logout")
            {
                close(sfd);
                break;
            }
            else
            {
                cout << "Invalid command" << endl;
            }
        }
    }
    else
    {
        cout << "Invalid command" << endl;
    }
    return 0;
}