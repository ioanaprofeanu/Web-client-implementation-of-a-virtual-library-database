#include <stdio.h>      /* printf, sprintf */
#include <stdlib.h>     /* exit, atoi, malloc, free */
#include <unistd.h>     /* read, write, close */
#include <string.h>     /* memcpy, memset */
#include <sys/socket.h> /* socket, connect */
#include <netinet/in.h> /* struct sockaddr_in, struct sockaddr */
#include <netdb.h>      /* struct hostent, gethostbyname */
#include <arpa/inet.h>
#include "parson.h"
#include "helpers.h"
#include "requests.h"

char *jwt_token = NULL;
char read_buffer[BUFLEN];
char cookie[BUFLEN];
int sockfd;

/**
 * @brief Create a json containing the user data received
 * from stdin
 * 
 * @return the serialized json string
 */
char* create_user_data_json() {
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    char *serialized_string = NULL;
    
    // get username and password from stdin and parse
    // the received information, then add a new object in
    // the json
    printf(GET_USERNAME);
    memset(read_buffer, 0, BUFLEN);
    fgets(read_buffer, BUFLEN, stdin);
    remove_trailing_newline(read_buffer);
    json_object_set_string(root_object, USERNAME, read_buffer);

    printf(GET_PASSWORD);
    memset(read_buffer, 0, BUFLEN);
    fgets(read_buffer, BUFLEN, stdin);
    remove_trailing_newline(read_buffer);
    json_object_set_string(root_object, PASSWORD, read_buffer);

    // create the serialized string with the json
    serialized_string = json_serialize_to_string_pretty(root_value);
    json_value_free(root_value);

    return serialized_string;
}

/**
 * @brief Handle the client registration command
 * 
 */
void client_register()
{
    char *serialized_string = NULL, *message, *response;
    char tokens[NO_TOKENS][BUFLEN];
    int error_code;

    // if the client is already connected, he cannot use the register command
    if (strlen(cookie) != 0) {
        printf("ERROR : Cannot register while logged in. Please log out first.\n\n");
        return;
    }

    // get the serialized string with the used data
    serialized_string = create_user_data_json();

    // create the post message and send it
    message = compute_post_request(HOST, REGISTER_ACCOUNT_ROUTE,
            PAYLOAD_TYPE_JSON, &serialized_string, 1, NULL, 0, NULL);
    send_to_server(sockfd, message);
    // retrieve the response from the server and get the first characters
    // from the message, which should contain the code error
    response = receive_from_server(sockfd);
    int no_tokens = get_tokens(response, tokens, NO_TOKENS);

    // if parsing the message failed, it means that the response was not sent
    // successfully
    if (no_tokens != NO_TOKENS) {
        printf("Something went wrong. Please try again.\n\n");
    } else {
        // extract the error code (it is the second word from the response)
        error_code = atoi(tokens[1]);

        // check for success or failure
        if (error_code == 201) {
           printf("%d - OK : User registered successfully. Welcome!\n\n",
                error_code);
        } else if (error_code == 400) {
            printf("%d - ERROR : Username already exists.\n\n", error_code);
        } else {
            printf("%d - ERROR : Something went wrong. Please try again.\n\n",
                error_code);
        }
    }

    // free memory and close socket
    json_free_serialized_string(serialized_string);
    free(message);
    free(response);
    close(sockfd);
}

/**
 * @brief Handle the client login command
 * 
 */
void client_login()
{
    char *serialized_string = NULL, *message, *response;
    char tokens[NO_TOKENS_UNTIL_COOKIE][BUFLEN];
    int error_code;

    // if the client is already connected, he cannot use the login command
    if (strlen(cookie) != 0) {
        printf("ERROR : You are already logged in.\n\n");
        return;
    }

    // get the serialized string with the used data
    serialized_string = create_user_data_json();

    // create the post message and send it
    message = compute_post_request(HOST, AUTHENTICATE_ACCOUNT_ROUTE,
            PAYLOAD_TYPE_JSON, &serialized_string, 1, NULL, 0, NULL);
    send_to_server(sockfd, message);
    // retrieve the response from the server and get 35 characters
    // from the message, which should contain the code error and the cookie
    response = receive_from_server(sockfd);
    int no_tokens = get_tokens(response, tokens, NO_TOKENS_UNTIL_COOKIE);

    // if parsing the message failed, it means that the response was not sent
    // successfully
    if (no_tokens < NO_TOKENS) {
        printf("Something went wrong. Please try again.\n\n");
    } else {
        // extract the error code (it is the second word from the response)
        error_code = atoi(tokens[1]);
        // if it is a success code
        if (error_code == 200) {
           printf("%d - OK : User authenticated successfully.\n", error_code);
           // iterate through the tokens until finding the word previous to
           // the actual cookie, then print and keep it in a variable
           for (int i = 0; i < no_tokens; i++) {
               if (strcmp(SET_COOKIE, tokens[i]) == 0) {
                   printf("Session cookie : %s\n\n", tokens[i + 1]);
                   memset(cookie, 0, BUFLEN);
                   strcpy(cookie, tokens[i + 1]);
                   break;
               }
           }
        // check it it is an error code
        } else if (error_code == 400) {
            printf("%d - ERROR : Credentials are not good or user does not exist.\n\n",
            error_code);
        } else {
            printf("%d - ERROR : Something went wrong. Please try again.\n\n",
            error_code);
        }
    }

    // free memory and close socket
    json_free_serialized_string(serialized_string);
    free(message);
    free(response);
    close(sockfd);
}

/**
 * @brief Handle the enter library command
 * 
 */
void client_enter_library()
{
    char *message, *response, *extract_jwt_json, tokens[NO_TOKENS][BUFLEN];
    char *serialized_string = NULL;
    int error_code;

    // send error message if the client is not connected or if he already has
    // access to the library
    if (strlen(cookie) == 0) {
        printf("ERROR : Cannot grant acces if not connected - please log in first.\n\n");
        return;
    } else if (jwt_token != NULL) {
        printf("ERROR : Library access already granted.\n\n");
        return;
    } else {
        // compose a get request, send it and get the response
        message = compute_get_request(HOST, ACCESS_ROUTE, NULL, cookie, 1, NULL);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        // extract the first tokens of the response
        int no_tokens = get_tokens(response, tokens, NO_TOKENS);

        // if no sufficient tokens were extracted, there is an issue with
        // the response
        if (no_tokens != NO_TOKENS) {
            printf("Something went wrong. Please try again.\n\n");
        } else {
            // extract the error code
            error_code = atoi(tokens[1]);
            // if it is a success
            if (error_code == 200) {
                printf("%d - OK : Library access granted.\n", error_code);
                // extract the jwt token, which is represented as a json
                extract_jwt_json = strstr(response, "{");
                JSON_Value *root_value = json_parse_string(extract_jwt_json);
                JSON_Object *root_object = json_value_get_object(root_value);
                // the jwt will be the value stored at the "token" key within
                // the object
                serialized_string = json_object_get_string(root_object, TOKEN);
                // store it in a variable and print it
                jwt_token = strdup(serialized_string);
                printf("Extracted JWT Token : %s\n\n", jwt_token);
                json_value_free(root_value);
                
            } else {
                printf("%d - ERROR : Something went wrong. Please try again.\n\n",
                error_code);
            }
        }
    }

    // free memory and close socket
    free(message);
    free(response);
    close(sockfd);
}

/**
 * @brief Handle the get books command
 * 
 */
void client_get_books()
{
    char *message, *response, *extract_books_array, tokens[NO_TOKENS][BUFLEN];
    char *book_title = NULL;
    JSON_Value *root_value = NULL;
    JSON_Array *root_array = NULL;
    int error_code, book_id;

    // send error message if the client is not connected or if he does not have
    // access to the library
    if (strlen(cookie) == 0) {
        printf("ERROR : Cannot get books if not connected - please log in first.\n\n");
        return;
    } else if (jwt_token == NULL) {
        printf("ERROR : Cannot get books if no access to library was granted.\n\n");
        return;
    } else {
        // compose a get request, send it and get the response
        message = compute_get_request(HOST, BOOKS_SUMARY_ROUTE, NULL,
                cookie, 1, jwt_token);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        // extract the first tokens of the response
        int no_tokens = get_tokens(response, tokens, NO_TOKENS);

        // if no sufficient tokens were extracted, there is an issue with
        // the response
        if (no_tokens != NO_TOKENS) {
            printf("Something went wrong. Please try again.\n\n");
        } else {
            // extract the error code
            error_code = atoi(tokens[1]);
            // if it was a success
            if (error_code == 200) {
                printf("%d - OK : Getting books from the library:\n\n",
                    error_code);
                // extract the json array from the json part of the message
                extract_books_array = strstr(response, "[");
                root_value = json_parse_string(extract_books_array);
                root_array = json_array(root_value);
                // iterate through the json array
                int array_length = json_array_get_count(root_array);
                int i = 0;
                while (i < array_length) {
                    // for each object, extract the title and id and print them
                    JSON_Object *book = json_array_get_object(root_array, i);
                    book_title = json_object_get_string(book, BOOK_TITLE);
                    book_id = json_object_get_number(book, BOOK_ID);
                    printf("ID : %d\nTitle : %s\n\n", book_id, book_title);
                    i++;
                }

            } else {
                // if it was an error code
                printf("%d - ERROR : Something went wrong. Please try again.\n\n",
                error_code);
            }
        }
    }

    // free the memory
    if (root_array != NULL) {
        json_array_clear(root_array);
    }
    if (root_value != NULL) {
        json_value_free(root_value);
    }
     
    free(message);
    free(response);
    // close the socket
    close(sockfd);
}

/**
 * @brief Handle the get book command
 * 
 */
void client_get_book()
{
    char *message, *response, tokens[NO_TOKENS][BUFLEN];
    char path[BUFLEN], get_book_id[MAX_LENGTH], *extract_book_data;
    char *serialized_string = NULL;
    int error_code, page_count;

    // send error message if the client is not connected or if he does not have
    // access to the library
    if (strlen(cookie) == 0) {
        printf("ERROR : Cannot get book if not connected - please log in first.\n\n");
        return;
    } else if (jwt_token == NULL) {
        printf("ERROR : Cannot get book if no access to library was granted.\n\n");
        return;
    } else {
        // get the wanted book id from stdin and parse it
        printf(GET_BOOK_ID);
        memset(get_book_id, 0, MAX_LENGTH);
        fgets(get_book_id, MAX_LENGTH, stdin);
        remove_trailing_newline(get_book_id);

        // check if the id is a valid number
        if (is_number(get_book_id) == 0) {
            printf("ERROR : Did not provide a valid ID. Please provide a valid number.\n\n");
            return;
        }

        // compose a get request, send it and get the response
        sprintf(path, "%s%s", BOOK_DETAILS_ROUTE, get_book_id);
        message = compute_get_request(HOST, path, NULL, cookie, 1, jwt_token);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        // extract the first tokens of the response
        int no_tokens = get_tokens(response, tokens, NO_TOKENS);

        // if no sufficient tokens were extracted, there is an issue with
        // the response
        if (no_tokens != NO_TOKENS) {
            printf("Something went wrong. Please try again.\n\n");
        } else {
            // extract the error code
            error_code = atoi(tokens[1]);
            // if it was a success
            if (error_code == 200) {
                printf("%d - OK : Getting details about book with ID %s:\n\n", error_code, get_book_id);
                // extract the json from the response
                extract_book_data = strstr(response, "{");
                // extract the json object and for each wanted entry, print the
                // value
                JSON_Value *root_value = json_parse_string(extract_book_data);
                JSON_Object *root_object = json_value_get_object(root_value);
                serialized_string = json_object_get_string(root_object, TITLE);
                printf("Title : %s\n", serialized_string);
                serialized_string = json_object_get_string(root_object, AUTHOR);
                printf("Author : %s\n", serialized_string);
                serialized_string = json_object_get_string(root_object, PUBLISHER);
                printf("Publisher : %s\n", serialized_string);
                serialized_string = json_object_get_string(root_object, GENRE);
                printf("Genre : %s\n", serialized_string);
                page_count = json_object_get_number(root_object, PAGE_COUNT);
                printf("Page count : %d\n\n", page_count);
                json_value_free(root_value);
            // if it was an error
            } else if (error_code == 404) {
                printf("%d - ERROR : No book with the given ID was found.\n\n", error_code);
            } else {
                printf("%d - ERROR : Something went wrong. Please try again.\n\n", error_code);
            }
        }
    }

    // free memory and close socket
    free(message);
    free(response);
    close(sockfd);
}

/**
 * @brief Handle the add book command
 * 
 */
void client_add_book()
{
    char *message, *response, tokens[NO_TOKENS][BUFLEN];
    char title[MAX_LENGTH], author[MAX_LENGTH], genre[MAX_LENGTH], publisher[MAX_LENGTH], page_count_string[MAX_LENGTH];
    char *serialized_string = NULL;
    int error_code, page_count;
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    // send error message if the client is not connected or if he does not have
    // access to the library
    if (strlen(cookie) == 0) {
        printf("ERROR : Cannot get book if not connected - please log in first.\n\n");
        json_value_free(root_value);
        return;
    } else if (jwt_token == NULL) {
        printf("ERROR : Cannot get book if no access to library was granted.\n\n");
        json_value_free(root_value);
        return;
    } else {
        // get the title from stdin and parse it
        printf(GET_TITLE);
        memset(title, 0, MAX_LENGTH);
        fgets(title, MAX_LENGTH, stdin);
        remove_trailing_newline(title);
        // check if the received title is valid
        if (strlen(title) <= 0) {
            printf("ERROR : Provided title not valid.\n\n");
            json_value_free(root_value);
            return;
        }
        // add entry to json object
        json_object_set_string(root_object, TITLE, title);

        // get the author from stdin and parse it
        printf(GET_AUTHOR);
        memset(author, 0, MAX_LENGTH);
        fgets(author, MAX_LENGTH, stdin);
        remove_trailing_newline(author);
        // check if the received author is valid
        if (strlen(author) <= 0) {
            printf("ERROR : Provided author not valid.\n\n");
            json_value_free(root_value);
            return;
        }
        // add entry to json object
        json_object_set_string(root_object, AUTHOR, author);

        // get the genre from stdin and parse it
        printf(GET_GENRE);
        memset(genre, 0, MAX_LENGTH);
        fgets(genre, MAX_LENGTH, stdin);
        remove_trailing_newline(genre);
        // check if the received genre is valid
        if (strlen(genre) <= 0) {
            printf("ERROR : Provided genre not valid.\n\n");
            json_value_free(root_value);
            return;
        }
        // add entry to json object
        json_object_set_string(root_object, GENRE, genre);

        // get the publisher from stdin and parse it
        printf(GET_PUBLISHER);
        memset(publisher, 0, MAX_LENGTH);
        fgets(publisher, MAX_LENGTH, stdin);
        remove_trailing_newline(publisher);
        // check if the received publisher is valid
        if (strlen(publisher) <= 0) {
            printf("ERROR : Provided publisher not valid.\n\n");
            json_value_free(root_value);
            return;
        }
        // add entry to json object
        json_object_set_string(root_object, PUBLISHER, publisher);

        // get the page count from stdin and parse it
        printf(GET_PAGE_COUNT);
        memset(page_count_string, 0, MAX_LENGTH);
        fgets(page_count_string, MAX_LENGTH, stdin);
        remove_trailing_newline(page_count_string);
        // check if the received page count is valid and if it is a number
        if (strlen(page_count_string) <= 0 ||
            is_number(page_count_string) == 0) {
            printf("ERROR : Provided page count not valid.\n\n");
            json_value_free(root_value);
            return;
        }
        // transform to int and add entry to json object
        page_count = atoi(page_count_string);
        json_object_set_number(root_object, PAGE_COUNT, page_count);

        // create the json payload string
        serialized_string = json_serialize_to_string_pretty(root_value);
        // compose a get request, send it and get the response
        message = compute_post_request(HOST, ADD_BOOK_ROUTE, PAYLOAD_TYPE_JSON,
                    &serialized_string, 1, cookie, 1, jwt_token);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        // extract the first tokens of the response
        int no_tokens = get_tokens(response, tokens, NO_TOKENS);

        // if no sufficient tokens were extracted, there is an issue with
        // the response
        if (no_tokens != NO_TOKENS) {
            printf("Something went wrong. Please try again.\n\n");
        } else {
            // extract the error code
            error_code = atoi(tokens[1]);
            // if it was a success
            if (error_code == 200) {
                printf("%d - OK : Successfully added book.\n\n", error_code);
            // if it was an error
            } else {
                printf("%d - ERROR : Failed adding book.\n\n", error_code);
            }
        }
    }

    // free memory and close socket
    json_value_free(root_value);
    json_free_serialized_string(serialized_string);
    free(message);
    free(response);
    close(sockfd);

}

/**
 * @brief Handle the book deletion command
 * 
 */
void client_delete_book()
{
    char *message, *response, tokens[NO_TOKENS][BUFLEN];
    char path[BUFLEN], get_book_id[MAX_LENGTH];
    int error_code;

    // send error message if the client is not connected or if he does not have
    // access to the library
    if (strlen(cookie) == 0) {
        printf("ERROR : Cannot delete book if not connected - please log in first.\n\n");
        return;
    } else if (jwt_token == NULL) {
        printf("ERROR : Cannot delete book if no access to library was granted.\n\n");
        return;
    } else {
        // get the book id from stdin and parse it
        printf(GET_BOOK_ID);
        memset(get_book_id, 0, MAX_LENGTH);
        fgets(get_book_id, MAX_LENGTH, stdin);
        remove_trailing_newline(get_book_id);

        // check if the id is a valid number
        if (is_number(get_book_id) == 0) {
            printf("ERROR : Did not provide a valid ID. Please provide a valid number.\n\n");
            return;
        }

        // compose a delete request, send it and get the response
        sprintf(path, "%s%s", DELETE_BOOK_ROUE, get_book_id);
        message = compute_delete_request(HOST, path, NULL, cookie, 1, jwt_token);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        // extract the first tokens of the response
        int no_tokens = get_tokens(response, tokens, NO_TOKENS);

        // if no sufficient tokens were extracted, there is an issue with
        // the response
        if (no_tokens != NO_TOKENS) {
            printf("Something went wrong. Please try again.\n\n");
        } else {
            // extract error code
            error_code = atoi(tokens[1]);
            // if it was a success
            if (error_code == 200) {
                printf("%d - OK : Deleted book with ID %s.\n\n", error_code, get_book_id);
            // if it was an error
            } else if (error_code == 404) {
                printf("%d - ERROR : No book with the given ID was found.\n\n", error_code);
            } else {
                printf("%d - ERROR : Something went wrong. Please try again.\n\n", error_code);
            }
        }
    }

    // free memory
    free(message);
    free(response);
    close(sockfd);
}

/**
 * @brief Handle the logout command
 * 
 */
void client_logout()
{
    char *message, *response, tokens[NO_TOKENS][BUFLEN];;
    int error_code;

    // send error message if the client is not connected
    if (strlen(cookie) == 0) {
        printf("ERROR : Tried to logout without being logged in. Please login first.\n\n");
        return;
    } else {
        // compose a get request, send it and get the response
        message = compute_get_request(HOST, ACCESS_ROUTE, NULL, cookie, 1, NULL);
        send_to_server(sockfd, message);
        response = receive_from_server(sockfd);
        // extract the first tokens of the response
        int no_tokens = get_tokens(response, tokens, NO_TOKENS);

        // if no sufficient tokens were extracted, there is an issue with
        // the response
        if (no_tokens != NO_TOKENS) {
            printf("Something went wrong. Please try again.\n\n");
        } else {
            // extract the error code
            error_code = atoi(tokens[1]);
            // if it was a success
            if (error_code == 200) {
                printf("%d - OK : Logged out successfully.\n\n", error_code);
                // reset the cookie and free the jwt memory
                memset(cookie, 0, BUFLEN);
                if (jwt_token != NULL) {
                    free(jwt_token);
                }
                jwt_token = NULL;
            // it it was an error 
            } else {
                printf("%d - ERROR : Something went wrong. Please try again.\n\n",
                        error_code);
            }
        }
    }

    // free memory
    free(message);
    free(response);
    close(sockfd);
}

/**
 * @brief Main function where we handle the received commands
 * in a while loop
 * 
 */
int main(int argc, char *argv[])
{
    while (TRUE) {
        // open the socket connection
        sockfd = open_connection(HOST, PORT, AF_INET, SOCK_STREAM, 0);
        DIE(sockfd < 0, "error sockfd\n");

        // read the command from stdin
        memset(read_buffer, 0, BUFLEN);
        fgets(read_buffer, BUFLEN, stdin);

        // depending on the given command and if it is received correctly,
        // make a specific action
        if (strncmp(read_buffer, REGISTER_COMMAND,
                sizeof(REGISTER_COMMAND) - 1) == 0) {
            client_register();

        } else if (strncmp(read_buffer, LOGIN_COMMAND,
                sizeof(LOGIN_COMMAND) - 1) == 0) {
            client_login();
            
        } else if (strncmp(read_buffer, ENTER_LIBRARY_COMMAND,
                sizeof(ENTER_LIBRARY_COMMAND) - 1) == 0) {
            client_enter_library();
        
        } else if (strncmp(read_buffer, GET_BOOKS_COMMAND,
                sizeof(GET_BOOKS_COMMAND) - 1) == 0) {
            client_get_books();
        
        } else if (strncmp(read_buffer, GET_BOOK_COMMAND,
                sizeof(GET_BOOK_COMMAND) - 1) == 0) {
            client_get_book();
        
        } else if (strncmp(read_buffer, ADD_BOOK_COMMAND,
                sizeof(ADD_BOOK_COMMAND) - 1) == 0) {
            client_add_book();

        } else if (strncmp(read_buffer, DELETE_BOOK_COMMAND,
                sizeof(DELETE_BOOK_COMMAND) - 1) == 0) {
            client_delete_book();

        } else if (strncmp(read_buffer, LOGOUT_COMMAND,
                sizeof(LOGOUT_COMMAND) - 1) == 0) {
            client_logout();
        
        } else if (strncmp(read_buffer, EXIT_COMMAND,
                sizeof(EXIT_COMMAND) - 1) == 0) {
            break;

        } else {
            // if the received command is wrong, print error message
            printf("ERROR : Entered wrong command. Please try again.\n\n");
            close(sockfd);
            continue;
        }
    }

    // close the socket connection and free the memory
    close(sockfd);
    if (jwt_token != NULL) {
        free(jwt_token);
    }

    return 0;
}
