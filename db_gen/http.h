#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define HTTP_IMPLEMENTATION
#include "picohttpparser.h"

int socket_connect(char *host, in_port_t port) {
  struct addrinfo hints, *result, *rp;
  memset(&hints, 0, sizeof(struct addrinfo));
  int sfd, s;

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = 0;
  hints.ai_protocol = 0;

  s = getaddrinfo(host, NULL, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "error: getaddrinfo failed: %d: %s", s, gai_strerror(s));
    return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;

    if (rp->ai_family == AF_INET) {
      struct sockaddr_in *addr = (struct sockaddr_in *)rp->ai_addr;
      addr->sin_port = htons(port);
    } else if (rp->ai_family == AF_INET6) {
      struct sockaddr_in6 *addr = (struct sockaddr_in6 *)rp->ai_addr;
      addr->sin6_port = htons(port);
    }

    if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1) break;

    close(sfd);
  }

  if (rp == NULL) {
    fprintf(stderr, "Could not connect");
    return -1;
  }

  freeaddrinfo(result);

  return sfd;
}

typedef struct HTTPClient {
  char *buf;
  int socket;
  int ok;
  uint64_t content_length;
  uint64_t nread;
  int done;
  int pending;
} HTTPClient;

HTTPClient http_get(string host, int port, string path) {
  int fd = socket_connect(host, port);

#define S(a) (a), sizeof(a) - 1
  write(fd, S("GET "));
  write(fd, path, path.len);
  write(fd, S(" HTTP/1.1\r\nHost: "));
  write(fd, host, host.len);
  write(fd, S("\r\nConnection: close\r\n\r\n"));
#undef S

#ifndef HTTP_READ_BUF_SIZE
#define HTTP_READ_BUF_SIZE 1 * 1024 * 1024
#endif

  char *buf = (char *)malloc(HTTP_READ_BUF_SIZE);
  int x = 0;
  int prevlen = 0;

  struct phr_header headers[100];
  uint64_t content_length = -1;
  size_t nr_headers = sizeof(headers) / sizeof(headers[0]);
  int status = 0;

  while (1) {
    int minor_version;
    const char *message;
    size_t msg_len;

    int nread = 0;
    while ((nread = read(fd, buf + x, HTTP_READ_BUF_SIZE - x)) == -1 &&
           errno == EINTR) {
    }
    if (nread <= 0) return (HTTPClient){.ok = 0};
    prevlen = x;
    x += nread;
    int pret = phr_parse_response(buf, x, &minor_version, &status, &message,
                                  &msg_len, headers, &nr_headers, prevlen);
    if (pret > 0) {
      if (status == 200) {
        for (size_t i = 0; i < nr_headers; i++) {
          if (strncmp(headers[i].name, "Content-Length", headers[i].name_len) ==
              0) {
            content_length = atoll(headers[i].value);
          }
        }
        memmove(buf, buf + pret, x - pret);
        return (HTTPClient){.buf = buf,
                            .socket = fd,
                            .ok = 1,
                            .content_length = content_length,
                            .nread = 0,
                            .done = 0,
                            .pending = x - pret};
      } else if (status == 301 || status == 302) {
        for (size_t i = 0; i < nr_headers; i++) {
          if (strncmp(headers[i].name, "Location", headers[i].name_len) == 0) {
            if (memcmp(headers[i].value, "http://", 7) != 0) {
              fprintf(stderr, "redirect to non-http url `%.*s`\n", (int)headers[i].value_len, headers[i].value);
              return (HTTPClient){.ok = 0};
            }
            string new_url = string(headers[i].value, headers[i].value_len).slice(7);
            int x = (char*)memchr(new_url, '/', new_url.len) - new_url;
            string newhost = new_url.slice(0, x).clone();
            string newpath = new_url.slice(x).clone();

            free(buf);
            close(fd);
            return http_get(newhost, port, newpath);
          }
        }
      }
    } else if (pret == -1) {
      free(buf);
      close(fd);
      return (HTTPClient){.ok = 0};
    } else if (pret != -2) {
      fprintf(stderr, "%d | %.*s\n", pret, x, buf);
    }
    // assert(pret == -2);
    if (x == sizeof(buf)) {
      free(buf);
      close(fd);
      return (HTTPClient){.ok = 0};
    }
  }
}

int http_read(HTTPClient *client) {
int flags = fcntl(client->socket, F_GETFL);
fcntl(client->socket, F_SETFL, flags & (~O_NONBLOCK));

  int pending = client->pending;
  client->nread += pending;
  int nread = pending;
  client->pending = 0;
  while (nread < HTTP_READ_BUF_SIZE) {
    int r;
    while ((r = read(client->socket, client->buf + nread,
                     HTTP_READ_BUF_SIZE - nread)) == -1 &&
           errno == EINTR) {
    }
    if (r < 0) {
      client->done = 1;
      return -1;
    }
    if (r == 0) {
      fprintf(stderr, "EOF at %d / %llu\n", nread, client->content_length);
    }
    nread += r;
    client->nread += r;
    if (client->nread >= client->content_length) {
      client->done = 1;
      return nread;
    }
  }

  flags = fcntl(client->socket, F_GETFL);
  fcntl(client->socket, F_SETFL, flags | (O_NONBLOCK));
  read(client->socket, client->buf, 0);

  return nread;
}

int http_free(HTTPClient *client) {
  free(client->buf);
  close(client->socket);
  return 0;
}
