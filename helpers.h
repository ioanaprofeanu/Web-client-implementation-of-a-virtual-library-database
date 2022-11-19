#ifndef _HELPERS_
#define _HELPERS_

#define BUFLEN 4096
#define LINELEN 1000

// defines used to easily follow the implementation
#define HOST "34.241.4.235"
#define PORT 8080
#define PAYLOAD_TYPE_JSON "application/json"
#define REGISTER_ACCOUNT_ROUTE "/api/v1/tema/auth/register"
#define AUTHENTICATE_ACCOUNT_ROUTE "/api/v1/tema/auth/login"
#define ACCESS_ROUTE " /api/v1/tema/library/access"
#define BOOKS_SUMARY_ROUTE " /api/v1/tema/library/books"
#define BOOK_DETAILS_ROUTE "/api/v1/tema/library/books/"
#define ADD_BOOK_ROUTE "/api/v1/tema/library/books/"
#define DELETE_BOOK_ROUE "/api/v1/tema/library/books/"
#define LOG_OUT_ROUTE "/api/v1/tema/auth/logout"

#define REGISTER_COMMAND "register"
#define GET_USERNAME "username="
#define GET_PASSWORD "password="
#define USERNAME "username"
#define PASSWORD "password"
#define LOGIN_COMMAND "login"
#define ENTER_LIBRARY_COMMAND "enter_library"

#define GET_BOOKS_COMMAND "get_books"
#define GET_BOOK_COMMAND "get_book"
#define GET_BOOK_ID "id="
#define BOOK_ID "id"
#define BOOK_TITLE "title"

#define ADD_BOOK_COMMAND "add_book"
#define GET_TITLE "title="
#define GET_AUTHOR "author="
#define GET_GENRE "genre="
#define GET_PUBLISHER "publisher="
#define GET_PAGE_COUNT "page_count="
#define TITLE "title"
#define AUTHOR "author"
#define GENRE "genre"
#define PUBLISHER "publisher"
#define PAGE_COUNT "page_count"

#define DELETE_BOOK_COMMAND "delete_book"
#define LOGOUT_COMMAND "logout"
#define EXIT_COMMAND "exit"

#define TRUE 1
#define ALL 1
#define NOT_ALL 1
#define NO_TOKENS 3
#define NO_TOKENS_UNTIL_COOKIE 35
#define SET_COOKIE "Set-Cookie:"
#define TOKEN "token"
#define MAX_LENGTH 100

#define DIE(assertion, call_description)	\
	do {									\
		if (assertion) {					\
			fprintf(stderr, "(%s, %d): ",	\
					__FILE__, __LINE__);	\
			perror(call_description);		\
			exit(EXIT_FAILURE);				\
		}									\
	} while(0)


// shows the current error
void error(const char *msg);

// adds a line to a string message
void compute_message(char *message, const char *line);

// opens a connection with server host_ip on port portno, returns a socket
int open_connection(char *host_ip, int portno, int ip_type, int socket_type, int flag);

// closes a server connection on socket sockfd
void close_connection(int sockfd);

// send a message to a server
void send_to_server(int sockfd, char *message);

// receives and returns the message from a server
char *receive_from_server(int sockfd);

// extracts and returns a JSON from a server response
char *basic_extract_json_response(char *str);

// remove the trailing newline at the end of a string
void remove_trailing_newline(char s[]);

// divide string into tokens
int get_tokens(char *command, char tokens[][BUFLEN], int max_tokens);

// check if given string is a number
int is_number(char s[]);

#endif
