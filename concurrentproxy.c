/*
 * concurrentproxy.c - CS:APP Concurrent Web Proxy
 *
 * TEAM MEMBERS:
 *     Mustafa Ali, eldmema0@sewanee.edu
 *
 * This concurrent web proxy server efficiently handles multiple HTTP GET requests simultaneously by managing each connection in a separate thread. 
 * It forwards requests to the intended servers unless the URLs are on a blocklist.
 * The proxy is compatible with HTTP/1.0 standards and seamlessly converts HTTP/1.1 requests from clients to HTTP/1.0 before forwarding them to the server.
 * Additionally, it maintains a log file to record each request, providing insights for monitoring and debugging purposes.
 */

#include "csapp.h"
#include <pthread.h>

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAX_BLOCKLIST 100
#define LOGFILE "proxy.log"

/* User agent header */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";
char blocklist[MAX_BLOCKLIST][MAXLINE];
int blocklist_count = 0;

typedef struct {
    int connfd;
    struct sockaddr_in clientaddr;
} thread_args;

pthread_mutex_t log_mutex;
FILE *log_file = NULL;

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
void *thread(void *vargp);
void proxy(thread_args *args);
void read_blocklist(const char *filename);
void log_request(char *log_entry);

int main(int argc, char **argv) {
    int listenfd, port;
    socklen_t clientlen;
    pthread_t tid;
    thread_args *args;
    struct sockaddr_in clientaddr;

    pthread_mutex_init(&log_mutex, NULL);
    log_file = fopen(LOGFILE, "a");
    if (!log_file) {
        fprintf(stderr, "Error opening log file.\n");
        exit(1);
    }

    read_blocklist("blocklist.txt");

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port>\n", argv[0]);
        exit(1);
    }
    port = atoi(argv[1]);
    char port_str[6];
    sprintf(port_str, "%d", port);
    listenfd = Open_listenfd(port_str);

    while (1) {
        clientlen = sizeof(struct sockaddr_in);
        args = malloc(sizeof(thread_args));
        args->connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
        args->clientaddr = clientaddr;
        pthread_create(&tid, NULL, thread, args);
    }
    fclose(log_file);
    pthread_mutex_destroy(&log_mutex);
}

/*
 * proxy - Handles one HTTP request/response transaction in a concurrent environment.
 * This function manages parsing the HTTP request, enforcing blocklist restrictions,
 * forwarding the request to the intended server if not blocked, handling the server's
 * response, and sending that response back to the client. It also logs each processed request.
*/
void proxy(thread_args *args) {
    int clientfd, port;
    ssize_t n;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char hostname[MAXLINE], pathname[MAXLINE], port_str[6];
    rio_t rio, server_rio;

    // Initialize RIO for reading from the client
    Rio_readinitb(&rio, args->connfd);
    if (!Rio_readlineb(&rio, buf, MAXLINE)) return; // Read the request line

    sscanf(buf, "%s %s %s", method, uri, version); // Parse the request line

    // Block non-GET and non-HEAD methods
    if (strcasecmp(method, "GET") != 0 && strcasecmp(method, "HEAD") != 0) {
        clienterror(args->connfd, method, "501", "Not Implemented", "This method is not implemented by the proxy");
        return;
    }

    // Check if the requested URI is on the blocklist
    for (int i = 0; i < blocklist_count; i++) {
        if (strstr(uri, blocklist[i]) != NULL) {
            clienterror(args->connfd, "Blocked", "403", "Forbidden", "This site is blocked by the proxy.");
            return;
        }
    }

    // Parse the URI to get hostname and path
    if (parse_uri(uri, hostname, pathname, &port) < 0) {
        clienterror(args->connfd, uri, "400", "Bad Request", "Proxy cannot parse the request");
        return;
    }

    // Connect to the destination server
    snprintf(port_str, sizeof(port_str), "%d", port);
    clientfd = Open_clientfd(hostname, port_str);
    if (clientfd < 0) {
        clienterror(args->connfd, hostname, "404", "Not found", "Cannot connect to the host");
        return;
    }

    // Send the modified request to the server
    Rio_readinitb(&server_rio, clientfd);
    snprintf(buf, sizeof(buf), "%s %s HTTP/1.0\r\nHost: %s\r\n", method, pathname[0] ? pathname : "/", hostname);
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "User-Agent: %sConnection: close\r\nProxy-Connection: close\r\n\r\n", user_agent_hdr);
    Rio_writen(clientfd, buf, strlen(buf));

    // Read the server's response and forward it to the client
    int size = 0;
    while ((n = Rio_readlineb(&server_rio, buf, MAXLINE)) != 0) {
        Rio_writen(args->connfd, buf, n);
        size += n;
    }

    // Log the request
    char log_entry[MAXLINE];
    format_log_entry(log_entry, &args->clientaddr, uri, size);
    log_request(log_entry);

    Close(clientfd);
}

/*
 * clienterror - Sends an HTTP error response to the client.
 * This function is used to notify the client of various server-side errors such as
 * invalid requests, blocked sites, or unsupported methods.
 */
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXLINE], body[MAXBUF];

    /* Build the HTTP response body */
    sprintf(body, "<html><title>Proxy Error</title>");
    sprintf(body, "%s<body bgcolor=""ffffff"">\r\n", body);
    sprintf(body, "%s%s: %s\r\n", body, errnum, shortmsg);
    sprintf(body, "%s<p>%s: %s\r\n", body, longmsg, cause);
    sprintf(body, "%s<hr><em>The CS:APP Proxy Server</em>\r\n", body);

    /* Print the HTTP response */
    sprintf(buf, "HTTP/1.0 %s %s\r\n", errnum, shortmsg);
    sprintf(buf, "%sContent-type: text/html\r\n", buf);
    sprintf(buf, "%sContent-length: %d\r\n\r\n", buf, (int)strlen(body));
    Rio_writen(fd, buf, strlen(buf));
    Rio_writen(fd, body, strlen(body));
}

/*
 * parse_uri - URI parser
 * 
 * Given a URI from an HTTP proxy GET request (i.e., a URL), extract
 * the host name, path name, and port.  The memory for hostname and
 * pathname must already be allocated and should be at least MAXLINE
 * bytes. Return -1 if there are any problems.
 */
int parse_uri(char *uri, char *hostname, char *pathname, int *port) {
    char *hostbegin;
    char *hostend;
    char *pathbegin;
    int len;

    if (strncasecmp(uri, "http://", 7) != 0) {
        hostname[0] = '\0';
        return -1;
    }

    /* Extract the host name */
    hostbegin = uri + 7;  // Move past "http://"
    hostend = strpbrk(hostbegin, " :/\r\n\0");
    if (!hostend) {
        hostname[0] = '\0';
        return -1;
    }
    len = hostend - hostbegin;
    strncpy(hostname, hostbegin, len);
    hostname[len] = '\0';

    /* Extract the port number */
    *port = 80; // Default HTTP port
    if (*hostend == ':') {
        *port = atoi(hostend + 1);
    }

    /* Extract the path */
    pathbegin = strchr(hostbegin, '/');
    if (pathbegin) {
        strcpy(pathname, pathbegin);
    } else {
        strcpy(pathname, "/");  // Default to root path if none is specified
    }

    return 0;
}

/*
 * format_log_entry - Create a formatted log entry in logstring. 
 * 
 * The inputs are the socket address of the requesting client
 * (sockaddr), the URI from the request (uri), and the size in bytes
 * of the response from the server (size).
 */
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size) {
    time_t now;
    char time_str[MAXLINE];
    char host_ip[INET_ADDRSTRLEN];

    /* Format the time */
    now = time(NULL);
    strftime(time_str, MAXLINE, "%a %d %b %Y %H:%M:%S %Z", localtime(&now));

    /* Convert the IP address to a string */
    inet_ntop(AF_INET, &(sockaddr->sin_addr), host_ip, INET_ADDRSTRLEN);

    /* Create the log entry */
    sprintf(logstring, "[%s] %s %s %d", time_str, host_ip, uri, size);
}

/*
 * thread - The starting point for each thread in a concurrent proxy server.
 * This function wraps the proxy functionality, allowing each connection to be handled
 * in a separate thread.
*/
void *thread(void *vargp) {
    thread_args *args = (thread_args *)vargp;
    pthread_detach(pthread_self());
    proxy(args);
    Close(args->connfd);
    free(vargp);
    return NULL;
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

FILE *log_file = NULL;  // Assuming you open this somewhere in main or before handling requests

/*
 * log_request - Logs a request to a log file.
*/
void log_request(char *log_entry) {
    pthread_mutex_lock(&log_mutex);
    if (log_file) {
        fprintf(log_file, "%s\n", log_entry);
        fflush(log_file);
    }
    pthread_mutex_unlock(&log_mutex);
}

/*
 * read_blocklist - Reads the blocklist from a specified file and stores the entries
 * in a global array. Each line in the file is treated as one blocklist entry.
*/
void read_blocklist(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) return;
    while (fgets(blocklist[blocklist_count], MAXLINE, file) != NULL) {
        blocklist[blocklist_count][strcspn(blocklist[blocklist_count], "\n")] = 0; // Remove newline
        if (strlen(blocklist[blocklist_count]) > 0) {
            blocklist_count++;
        }
    }
    fclose(file);
}