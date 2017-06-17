#include <pthread.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <fcntl.h>
#include <limits.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <linux/netfilter_ipv4.h>

struct proxy {
    struct sockaddr_in sin;
    int local;
    int remote;
    int serial; /* connection number */
    int sent; /* bytes local->remote */
    int recv; /* bytes remote->local */
};

static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static int connections = 0; /* current number of connections */
static int conn_serial = 0; /* connection serial number */
static bool debug = false;

static void *writer (void *);
static void *accepter (void *);
static int iread (int, void *, size_t, const char *);
static int iwrite (int, const void *, size_t, const char *);
static void logger (int pri, const char *fmt, ...) __attribute__ ((__format__ (__printf__, 2, 3)));

void usage (const char *progname)
{
    printf("usage: %s [OPTION]... PROXYHOST PROXYPORT\n"
	   "\n"
	   "Transparent proxy for local connections to a proxy supporting CONNECT\n"
	   "\n"
	   " -p, --port            Port to listen on (default: 3128)\n"
	   " -m, --max-connections Maximum number of concurrent connections\n"
	   "                       (default: 256)\n"
	   " -i, --pidfile         Record the pid of %s (default: none)\n"
	   " -d, --debug           Turn on debugging\n"
	   " --version             Version number (" VERSION ")\n"
	   " --help                This help\n"
	   "\n"
	   "To proxy all outgoing connections to PROXYHOST you will need something like this\n"
	   "in iptables:\n"
	   "\n"
	   "    iptables -t nat -A OUTPUT -p tcp -m tcp -d PROXYHOST/32 -j ACCEPT\n"
	   "    iptables -t nat -A OUTPUT -p tcp -m tcp -d 127.0.0.0/8 -j ACCEPT\n"
	   "    iptables -t nat -A OUTPUT -p tcp -m tcp -d 10.0.0.0/8 -j ACCEPT\n"
	   "    iptables -t nat -A OUTPUT -p tcp -m tcp -d 172.16.0.0/16 -j ACCEPT\n"
	   "    iptables -t nat -A OUTPUT -p tcp -m tcp -d 192.168.0.0/16 -j ACCEPT\n"
	   "    iptables -t nat -A OUTPUT -p tcp -m tcp ! --dport 3128\\\n"
	   "             -j REDIRECT --to-port PROXYPORT\n"
	   "\n"
	   "You may want to add further ACCEPT commands (before the REDIRECT) for other\n"
	   "locally reachable networks.\n",
	   progname, progname);
}


int main (int argc, char **argv)
{
    struct option options[] = {
	{ "port",            required_argument, NULL, 'p' },
	{ "pidfile",         required_argument, NULL, 'i' },
	{ "max-connections", required_argument, NULL, 'm' },
	{ "debug",           no_argument,       NULL, 'd' },
	{ "version",         no_argument,       NULL, 'v' },
	{ "help",            no_argument,       NULL, 'h' },
	{ NULL, 0, NULL, 0 }
    };
    const char *progname;
    int port = 3128;
    int max_connections = 256;
    char *pidfile = NULL;
    pthread_attr_t attr;
    struct sockaddr_in sin;
    struct sockaddr_in proxy;
    int s, i;

    signal(SIGPIPE, SIG_IGN);
    if ((progname = strrchr(argv[0], '/')))
	progname++;
    else
	progname = argv[0];

    while ((i = getopt_long(argc, argv, "dp:i:m:", options, NULL)) >= 0) {
	switch (i) {
	case 'd':
	    debug = !debug;
	    break;
	case 'p':
	    port = atoi(optarg);
	    break;
	case 'i':
	    pidfile = optarg;
	    break;
	case 'm':
	    max_connections = atoi(optarg);
	    break;
	case 'v':
	    printf("%s " VERSION "\n", progname);
	    exit(0);
	case 'h':
	    usage(progname);
	    exit(0);
	default:
	    fprintf(stderr, "Try \"%s --help\" for more information.\n", progname);
	    exit(1);
	}
    }
    argv += optind;
    argc -= optind;
    if (argc != 2) {
	fprintf(stderr,
		"Wrong arguments, expecting PROXYHOST PROXYPORT\n"
		"Try \"%s --help\" for more information.\n", progname);
	exit(1);
    }

    memset(&proxy, 0, sizeof(proxy));
    proxy.sin_family = AF_INET;
    if (!inet_aton(argv[0], &proxy.sin_addr)) {
	struct hostent *hp;
	if ((hp = gethostbyname(argv[0])))
	    memcpy(&proxy.sin_addr, hp->h_addr, hp->h_length);
	else {
	    fprintf(stderr, "%s: unknown host %s\n", progname, argv[0]);
	    exit(1);
	}
    }
    proxy.sin_port = htons(atoi(argv[1]));
    
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    i = 1;
    if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0
	|| setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) < 0
	|| bind(s, (struct sockaddr *) &sin, sizeof(sin)) < 0
	|| listen(s, SOMAXCONN) < 0) {
	perror("socket");
	exit(1);
    }
    openlog(progname, LOG_PID | (debug ? LOG_PERROR : 0), LOG_DAEMON);
    if (!debug) {
	int fd = open("/dev/null", O_RDWR);
	pid_t pid = fork();
	if (pid < 0) {
	    perror(progname);
	    exit(1);
	} else if (pid != 0)
	    exit(0);
	setsid();
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	close(fd);
	if (pidfile) {
	    FILE *f = fopen(pidfile, "w");
	    fprintf(f, "%d\n", getpid());
	    fclose(f);
	}
    }
    
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    for (;;) {
	pthread_t t;
	struct proxy *data;
	int r;

	if ((r = accept(s, NULL, NULL)) < 0) {
	    if (errno == EINTR)
		continue;
	    logger(LOG_CRIT, "accept: %m");
	    exit(1);
	}
	pthread_mutex_lock(&conn_mutex);
	if (connections >= max_connections) {
	    logger(LOG_ERR, "too many connections (%d)", max_connections);
	    close(r);
	} else {
	    connections++;
	    data = calloc(1, sizeof(struct proxy));
	    data->sin = proxy;
	    data->serial = conn_serial++;
	    data->local = r;
	    data->remote = -1;
	    pthread_create(&t, &attr, accepter, data);
	}
	pthread_mutex_unlock(&conn_mutex);
    }
}

static void *accepter (void *data)
{
    char buf[8192];
    char *ptr;
    pthread_t t;
    pthread_attr_t attr;
    struct proxy *proxy = data;
    struct sockaddr_in sin;
    socklen_t len = sizeof(sin);
    void *status;
    int n, m;

    if (getsockopt(proxy->local, SOL_IP, SO_ORIGINAL_DST, &sin, &len) < 0) {
	logger(LOG_ERR, "cannot get original IP address: %m");
	goto done;
    }
    logger(LOG_INFO, "[%d] connect: %s:%d\n",
	   proxy->serial, inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    if (sin.sin_addr.s_addr == proxy->sin.sin_addr.s_addr) {
	logger(LOG_CRIT, "connection loop detected -- missing iptables entry for proxy?\n");
	goto done;
    }
    snprintf(buf, sizeof(buf), "CONNECT %s:%d HTTP/1.0\r\n\r\n",
	     inet_ntoa(sin.sin_addr), ntohs(sin.sin_port));
    if ((proxy->remote = socket(PF_INET, SOCK_STREAM, 0)) < 0
	|| connect(proxy->remote, (struct sockaddr *) &proxy->sin, sizeof(proxy->sin)) < 0
	|| write(proxy->remote, buf, strlen(buf)) != strlen(buf)) {
	logger(LOG_ERR, "proxy connect: %m");
	goto done;
    }
    n = 0;
    ptr = buf;
    while (n < 2) {
	if (iread(proxy->remote, ptr, 1, "proxy read") != 1)
	    goto done;
	if (*ptr == '\n')
	    n++;
	else if (*ptr != '\r')
	    n = 0;
	ptr++;
    }
    *ptr = '\0';
    if (sscanf(buf, "HTTP/1.%*d %d", &n) != 1 || n/100 != 2) {
	if ((ptr = strchr(buf, '\r')) || (ptr = strchr(buf, '\n')))
	    *ptr = '\0';
	logger(LOG_ERR, "bad proxy response: %s:%d %s",
	       inet_ntoa(sin.sin_addr), ntohs(sin.sin_port), buf);
	goto done;
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_create(&t, &attr, writer, data);
    for (;;) {
	if ((n = iread(proxy->local, buf, sizeof(buf), "local read")) < 0)
	    goto done;
	if (n == 0) {
	    /* propagate local EOF */
	    shutdown(proxy->remote, SHUT_WR);
	    break;
	}
	proxy->sent += n;
	ptr = buf;
	while (n > 0) {
	    if ((m = iwrite(proxy->remote, ptr, n, "remote write")) < 0)
		goto done;
	    n -= m;
	    ptr += m;
	}
	
    }
    /* wait for writer */
    pthread_join(t, &status);
  done:
    pthread_mutex_lock(&conn_mutex);
    logger(LOG_INFO, "[%d] disconnect send %dkB received %dkB\n", proxy->serial, (proxy->sent+1023)/1024, (proxy->recv+1023)/1024);
    connections--;
    pthread_mutex_unlock(&conn_mutex);
    if (proxy->local >= 0)
	close(proxy->local);
    if (proxy->remote >= 0)
	close(proxy->remote);
    free(data);
    pthread_exit(NULL);
}

static void *writer (void *data)
{
    struct proxy *proxy = data;
    char buf[8192];
    int n;

    while ((n = iread(proxy->remote, buf, sizeof(buf), "remote read")) > 0)
    {
	char *ptr = buf;
	int m;
	proxy->recv += n;
	while (n > 0) {
	    if ((m = iwrite(proxy->local, ptr, n, "local write")) < 0)
		goto done;
	    n -= m;
	    ptr += m;
	}
    }
  done:
    /* propagate remote EOF */
    shutdown(proxy->local, SHUT_WR);
    pthread_exit(NULL);
}
	   
    
static int iread (int fd, void *buf, size_t count, const char *msg)
{
    int n;
    do {
	n = read(fd, buf, count);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
	logger(LOG_WARNING, "%s: %m", msg);
    return n;
}

static int iwrite (int fd, const void *buf, size_t count, const char *msg)
{
    int n;
    do {
	n = write(fd, buf, count);
    } while (n < 0 && errno == EINTR);
    if (n < 0)
	logger(LOG_WARNING, "%s: %m", msg);
    return n;
}

static void logger (int pri, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&log_mutex);
    vsyslog(pri, fmt, ap);
    pthread_mutex_unlock(&log_mutex);
    va_end(ap);
}
