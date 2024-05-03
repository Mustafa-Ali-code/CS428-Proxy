/*
 * proxy.c - CS:APP Web proxy
 *
 * TEAM MEMBERS:
 *     Mustafa Ali, eldmema0@sewanee.edu
 *
 * This proxy server accepts HTTP GET requests and forwards them to the intended server,
 * unless the request is for a URL on the blocklist. It also logs each request in a log file.
 * The proxy supports HTTP/1.0 and modifies HTTP/1.1 requests from the client to HTTP/1.0
 * requests for the server.
 */

#include "csapp.h"

/* Recommended max cache and object sizes */
#define MAX_CACHE_SIZE 1049000
#define MAX_OBJECT_SIZE 102400
#define MAX_BLOCKLIST 100
#define LOGFILE "proxy.log"

/* User agent header */
static const char *user_agent_hdr = "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:10.0.3) Gecko/20120305 Firefox/10.0.3\r\n";

/* Blocklist */
char blocklist[MAX_BLOCKLIST][MAXLINE];
int blocklist_count = 0;

/*
 * Function prototypes
 */
int parse_uri(char *uri, char *target_addr, char *path, int *port);
void format_log_entry(char *logstring, struct sockaddr_in *sockaddr, char *uri, int size);
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg);
void read_blocklist(const char *filename);
void proxy(int connfd, FILE *log, struct sockaddr_in clientaddr);

int main(int argc, char **argv) {
    int listenfd, connfd, port;
    socklen_t clientlen;
    struct sockaddr_in clientaddr;
    FILE *log;

    /* Read blocklist */
    read_blocklist("blocklist.txt");


    /* Open log file */
    log = fopen(LOGFILE, "a");
    if (!log) {
        fprintf(stderr, "Error opening log file.\n");
        exit(1);
    }

    /* Check command line args */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <port number>\n", argv[0]);
        exit(1);
    }
    port = atoi(argv[1]);

    char port_str[6]; // Buffer to hold the port number as string
    sprintf(port_str, "%d", port); // Convert integer port to string

    listenfd = Open_listenfd(port_str); // Pass string instead of integer
    while (1) {
        clientlen = sizeof(clientaddr);
        connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
        proxy(connfd, log, clientaddr);
        Close(connfd);
    }
    fclose(log);
}

/*
 * proxy - Handle one HTTP request/response transaction.
 * This function manages the full lifecycle of a proxy request, including parsing
 * the HTTP request, checking against a blocklist, forwarding the request to the target
 * server if not blocked, and returning the response to the client. It also logs the request.
 */
void proxy(int connfd, FILE *log, struct sockaddr_in clientaddr) {
    int clientfd, port, size = 0;
    ssize_t n;
    char buf[MAXLINE], method[MAXLINE], uri[MAXLINE], version[MAXLINE];
    char hostname[MAXLINE], pathname[MAXLINE], port_str[6];
    rio_t rio, server_rio;

    Rio_readinitb(&rio, connfd);
    if (!Rio_readlineb(&rio, buf, MAXLINE))
        return;

    sscanf(buf, "%s %s %s", method, uri, version);
    if (strcasecmp(method, "GET") && strcasecmp(method, "HEAD")) {
        clienterror(connfd, method, "501", "Not Implemented", "Method not implemented");
        return;
    }

    // Enhanced URI parsing and blocklist checking
    if (parse_uri(uri, hostname, pathname, &port) < 0) {
        clienterror(connfd, uri, "400", "Bad Request", "Cannot parse the request");
        return;
    }

    for (int i = 0; i < blocklist_count; i++) {
        if (strcasecmp(hostname, blocklist[i]) == 0) { // Case-insensitive comparison of hostname and blocklist
            clienterror(connfd, "Blocked", "403", "Forbidden", "This site is blocked by the proxy.");
            return;
        }
    }

    snprintf(port_str, sizeof(port_str), "%d", port);
    clientfd = Open_clientfd(hostname, port_str);
    if (clientfd < 0) {
        clienterror(connfd, hostname, "404", "Not Found", "Cannot connect to the host");
        return;
    }

    /* Forward the modified request */
    snprintf(buf, sizeof(buf), "%s %s HTTP/1.0\r\nHost: %s\r\n", method, pathname[0] ? pathname : "/", hostname);
    snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%sConnection: close\r\nProxy-Connection: close\r\n\r\n", user_agent_hdr);
    Rio_writen(clientfd, buf, strlen(buf));

    /* Read and forward the server response, while counting bytes */
    Rio_readinitb(&server_rio, clientfd);
    while ((n = Rio_readlineb(&server_rio, buf, MAXLINE)) != 0) {
        Rio_writen(connfd, buf, n);
        size += n;
    }

    /* Log the request */
    char log_entry[MAXLINE];
    format_log_entry(log_entry, &clientaddr, uri, size);
    fprintf(log, "%s\n", log_entry);
    fflush(log);

    Close(clientfd);
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

/*
 * clienterror - Sends an HTTP error response to the client. This function is used to
 * inform the client about errors such as unsupported methods or blocked resources.
 */
void clienterror(int fd, char *cause, char *errnum, char *shortmsg, char *longmsg) {
    char buf[MAXLINE], body[MAXBUF];

    sprintf(body, "<html><title>Proxy Error</title><body bgcolor=\"ffffff\">%s: %s<p>%s: %s<hr><em>The CS:APP Proxy Server</em></body></html>", errnum, shortmsg, longmsg, cause);
    sprintf(buf, "HTTP/1.0 %s %s\r\nContent-type: text/html\r\nContent-length: %d\r\n\r\n", errnum, shortmsg, (int)strlen(body));
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
    char *hostbegin, *hostend, *pathbegin;
    int len;

    if (strncasecmp(uri, "http://", 7) == 0) {
        hostbegin = uri + 7;
    } else if (strncasecmp(uri, "https://", 8) == 0) {
        hostbegin = uri + 8;
    } else {
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