#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>

/* For access to open() and associated flags: */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>

#include <time.h>

#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define LOGFILE_PATH "/var/log/udp-portknock.log"
#define PIDFILE_PATH "/var/run/udp-portknock.pid"
typedef struct 
{
	/* Command-line options */
	char * net_interface;
	char * command;
	unsigned short udp_port;

	FILE * logfile;
	pcap_t * pcap_handle;
	struct bpf_program filter_compiled;
	unsigned int ip_offset;
	int signal;
} PortKnock;

/* This needs to be global in order to be modified in signal handlers */
PortKnock * pk;

PortKnock * PortKnock_new(void);
void PortKnock_delete(PortKnock *);
void PortKnock_fill_parameters(PortKnock *, int, char * const[]);
int PortKnock_open_log(PortKnock *);
void PortKnock_write_pidfile(void);
int PortKnock_setup(PortKnock *);
void PortKnock_run(PortKnock *);

void signal_handler(int);
int logprintf(FILE *, const char *, ...);

int main(int argc, char * argv[])
{
	/* Check that program runs as root, required for libpcap */
	if (getuid() != 0) {
		fprintf(stderr, "%s: interface listening requires root privileges.\n", argv[0]);
		return 1;
	}

	/* Fill state with command-line options */
	pk = PortKnock_new();
	PortKnock_fill_parameters(pk, argc, argv);
	if (pk->net_interface == NULL) {
		fprintf(stderr, "%s: must supply a network interface to listen to.\n", argv[0]);
		PortKnock_delete(pk);
		return 1;
	}
	if (pk->command == NULL) {
		fprintf(stderr, "%s: must supply a command to run on packet match.\n", argv[0]);
		PortKnock_delete(pk);
		return 1;
	}
	if (pk->udp_port == 0) {
		fprintf(stderr, "%s: must supply an UDP port to listen to.\n", argv[0]);
		PortKnock_delete(pk);
		return 1;
	}
	
	/* Become a daemon */
	if (daemon(0, 0) < 0) {
		fprintf(stderr, "%s: failed to daemonize.\n", argv[0]);
		PortKnock_delete(pk);
		return 1;
	}
	
	/* Open logfile and redirect stdout/stderr to it, write PID file */
	if (!PortKnock_open_log(pk)) {
		PortKnock_delete(pk);
		return 1;
	}
	PortKnock_write_pidfile();
	logprintf(pk->logfile, "Log file opened correctly\n");
	logprintf(pk->logfile, "Will run %s on valid port knock.\n", pk->command);
	
	if (!PortKnock_setup(pk)) {
		logprintf(pk->logfile, "FATAL: unable to setup port listening!\n");
		PortKnock_delete(pk);
		return 1;
	}

    siginterrupt(SIGCHLD, 0);
    siginterrupt(SIGINT, 1);
    siginterrupt(SIGTERM, 1);
    siginterrupt(SIGHUP, 1);
    siginterrupt(SIGQUIT, 1);
	signal(SIGCHLD, SIG_IGN);
	signal(SIGTERM, signal_handler);
	signal(SIGQUIT, signal_handler);
	signal(SIGINT,  signal_handler);
	signal(SIGHUP,  signal_handler);
	
	PortKnock_run(pk);
	
	logprintf(pk->logfile, "Shutting down...\n");
	signal(SIGTERM, SIG_DFL);
	signal(SIGQUIT, SIG_DFL);
	signal(SIGINT,  SIG_DFL);
	signal(SIGHUP,  SIG_DFL);

	PortKnock_delete(pk);
	return 0;
}

PortKnock * PortKnock_new(void)
{
	pk = (PortKnock *)malloc(sizeof(PortKnock));
	pk->net_interface = NULL;
	pk->command = NULL;
	pk->udp_port = 0;
	pk->logfile = NULL;
	pk->signal = 0;
	pk->pcap_handle = NULL;
	pk->ip_offset = 0;

	return pk;
}

void PortKnock_delete(PortKnock * pk)
{
	if (pk->pcap_handle != NULL) pcap_close(pk->pcap_handle);
	if (pk->logfile != NULL) fclose(pk->logfile);
	if (pk->command != NULL) free(pk->command);
	if (pk->net_interface != NULL) free(pk->net_interface);
	unlink(PIDFILE_PATH);
	free(pk);
}

void signal_handler(int sig)
{
	pk->signal = sig;
}

/*  
-i interfaz a escuchar
-s programa a ejecutar
-p puerto UDP a escuchar
*/

void PortKnock_fill_parameters(PortKnock * pk, int argc, char * const argv[])
{
	int option;
	
	while ((option = getopt(argc, argv, "i:s:p:")) != -1) {
		switch (option) {
		case 'i':
			pk->net_interface = strdup(optarg);
			break;
		case 's':
			pk->command = strdup(optarg);
			break;
		case 'p':
			sscanf(optarg, "%hu", &(pk->udp_port));
			break;
		}
	}
}

int PortKnock_open_log(PortKnock * pk)
{
	/*	Se abre el archivo a través de open() para tener acceso al descriptor de
	    archivo. A continuación se crea un flujo estándar con fdopen(). Se 
	    duplica el descriptor de la bitácora como stdout (descriptor 1) y stderr
		(descriptor 2) para que cualquier llamada a printf(), fprintf(stderr) o 
		a perror() sea dirigida al archivo de bitácora. */
	int handle = open(LOGFILE_PATH,
		O_CREAT | O_APPEND | O_WRONLY,
		S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
	if (handle < 0) return 0;
	pk->logfile = fdopen(handle, "a");
	if (pk->logfile == NULL) {
		close(handle);
		return 0;
	}
	dup2(handle, 2); dup2(handle, 1);
	fcntl(handle, F_SETFD, fcntl(handle, F_GETFD) | FD_CLOEXEC);
	
	return 1;
}

void PortKnock_write_pidfile(void)
{
	FILE * pidfile;

	/* Write PID of current process into file */
	pidfile = fopen(PIDFILE_PATH, "w");
	if (pidfile != NULL) {
		fprintf(pidfile, "%u", getpid());
		fclose(pidfile);
	}
}

int PortKnock_setup(PortKnock * pk)
{
	char filter_source[64];	
	char errbuf[PCAP_ERRBUF_SIZE];
	int datalink;

	if (NULL == (pk->pcap_handle = pcap_open_live(pk->net_interface, 65535, 0, 0, errbuf))) {
		logprintf(pk->logfile, "FATAL: unable to listen to interface %s - %s\n",
			pk->net_interface, errbuf);
		return 0;
	}
	snprintf(filter_source, sizeof(filter_source), "udp port %u", pk->udp_port);
	if (pcap_compile(pk->pcap_handle, &pk->filter_compiled, filter_source, 0, /*PCAP_NETMASK_UNKNOWN*/ 0xffffffff) < 0) {
		logprintf(pk->logfile, "FATAL: unable to prepare filter '%s' on interface %s - %s\n",
			filter_source, pk->net_interface, pcap_geterr(pk->pcap_handle));
		return 0;
	}
	if (pcap_setfilter(pk->pcap_handle, &pk->filter_compiled) < 0) {
		logprintf(pk->logfile, "FATAL: unable to apply filter '%s' on interface %s - %s\n",
			filter_source, pk->net_interface, pcap_geterr(pk->pcap_handle));
		return 0;
	}
	pcap_setnonblock(pk->pcap_handle, 1, errbuf);

    // Figure out offset at which IP payload starts
    switch((datalink = pcap_datalink(pk->pcap_handle))) {
    case DLT_EN10MB:
        pk->ip_offset = 14;
        break;
    case DLT_IEEE802:
        pk->ip_offset = 22;
        break;
    case DLT_FDDI:
        pk->ip_offset = 21;
        break;
    case DLT_PPP:
        pk->ip_offset = 12;
        break;
    case DLT_NULL:
        pk->ip_offset = 4;
        break;
    case DLT_RAW:
        pk->ip_offset = 0;
        break;
    case DLT_LINUX_SLL:
        pk->ip_offset = 16;
        break;
    default:
        logprintf(pk->logfile, "ERR: unknown datalink type %u, using IP offset 0\n", datalink);
        pk->ip_offset = 0;
    }
	return 1;
}

void PortKnock_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void PortKnock_run(PortKnock * pk)
{
	int pcap_socket;
	fd_set fdset;
	struct timeval tv;
	
	pcap_socket = pcap_get_selectable_fd(pk->pcap_handle);
	logprintf(pk->logfile, "Starting UDP port listening...\n");
	do {
        int iRet;

		tv.tv_sec = 0;
		tv.tv_usec = 250000;
		FD_ZERO(&fdset);
		FD_SET(pcap_socket, &fdset);
		iRet = select(pcap_socket + 1, &fdset, NULL, NULL, &tv);

		if (iRet > 0) {
			while (pk->signal == 0 && pcap_dispatch(pk->pcap_handle, -1, PortKnock_packet, (u_char *)pk) > 0);
		}
		if (pk->signal == SIGHUP) {
			/* logrotate asks to close and reopen the log file */
			logprintf(pk->logfile, "SIGHUP received, closing and reopening logfile...\n");
			fclose(pk->logfile); pk->logfile = NULL;
			if (PortKnock_open_log(pk)) {
				pk->signal = 0;
				logprintf(pk->logfile, "SIGHUP received, logfile reopening successful...\n");
			}
		}
	} while (pk->signal == 0);
	logprintf(pk->logfile, "Stopping UDP port listening due to signal %u...\n", pk->signal);
}

int PortKnock_is_valid_knock(PortKnock *, const u_char *, unsigned int, char **, char **);

void PortKnock_packet(u_char * data, const struct pcap_pkthdr * packet_info, const u_char * packet_data)
{
	PortKnock * pk = (PortKnock *)data;
	char * username;
	char * encoded;

    struct ip * header_ip = (struct ip *)(packet_data + pk->ip_offset);
    struct udphdr * header_udp = (struct udphdr *)(packet_data + pk->ip_offset + sizeof(struct ip));
    const u_char * payload = packet_data + pk->ip_offset + sizeof(struct ip) + sizeof(struct udphdr);
    unsigned int payload_length;

	if (header_ip->ip_p != IPPROTO_UDP) {
		/* logprintf(pk->logfile, "DEBUG: captured packet is not UDP\n"); */
		return;
	}
	if ((ntohs(header_udp->dest) != pk->udp_port)) {
		/* logprintf(pk->logfile, "DEBUG: captured packet is not intended for listening port\n"); */
		return;
	}
	if (packet_info->caplen < pk->ip_offset + sizeof(struct ip) + sizeof(struct udphdr)) {
		/* logprintf(pk->logfile, "DEBUG: captured packet has been truncated or is too small\n"); */
		return;
	}
	payload_length = packet_info->caplen - (pk->ip_offset + sizeof(struct ip) + sizeof(struct udphdr));
	if (payload_length > header_udp->len - sizeof(struct udphdr))
		payload_length = header_udp->len - sizeof(struct udphdr);
	
	if (PortKnock_is_valid_knock(pk, payload, payload_length, &username, &encoded)) {
		/* logprintf(pk->logfile, "DEBUG: port knock for user %s payload %s\n", username, encoded); */
		int child_pid = fork();
		if (child_pid < 0) {
			logprintf(pk->logfile, "ERR: failed to fork() for handler command - %s\n", strerror(errno));
		} else if (child_pid == 0) {

			/* Must restore all the signals, especially SIGCHLD */
			signal(SIGCHLD, SIG_DFL);
			signal(SIGTERM, SIG_DFL);
			signal(SIGQUIT, SIG_DFL);
			signal(SIGINT,  SIG_DFL);
			signal(SIGHUP,  SIG_DFL);

			execl(pk->command,
				pk->command, pk->net_interface, inet_ntoa(header_ip->ip_src), username, encoded, NULL);
			
			/* Should never reach here */
			logprintf(pk->logfile, "ERR: failed to execl() command %s - %s\n", pk->command, strerror(errno));
			exit(1);
		}

		free(encoded);
		free(username);
	}
}

int PortKnock_is_valid_knock(PortKnock * pk, const u_char * data, 
	unsigned int length, char ** puser, char ** pencoded)
{
	/* A valid payload contains a nonempty username, followed by a colon, followed
	   by a base64-encoded binary string. The base64-encoded string consists of
	   the characters A-Z,a-z,0-9,+,/ and trailing = */
	const u_char * p = data;
	
	*puser = *pencoded = NULL;
	if (length < 6) return 0;	/* Not enough data for valid payload */

	while (p - data < length && isascii(*p) && (isalnum(*p) || *p == '_' || *p == '@' || *p == '.')) p++;
	if (p == data) return 0;			/* Data starts with invalid character */
	if (p - data > length - 5) return 0;	/* No colon delimiter found */
	if (*p != ':') return 0;			/* Found an invalid character */
	
	*puser = (char *)calloc(1, 1 + (p - data));
	memcpy(*puser, data, p - data);
	p++; length -= (p - data); data = p;
	
	while (p - data < length && isascii(*p) && (isalnum(*p) || *p == '+' || *p == '/')) p++;
	if (p == data) goto invalid_encoding;		/* Encoding starts with invalid character */
	if (p - data < length && *p != '=') goto invalid_encoding;
	while (p - data < length && *p == '=') p++;
	if (p - data < length) goto invalid_encoding;

	*pencoded = (char *)calloc(1, 1 + (p - data));
	memcpy(*pencoded, data, p - data);
	return 1;
		
invalid_encoding:
	if (*puser != NULL) free(*puser); *puser = NULL;
	return 0;	
}

int logprintf(FILE * hLog, const char * s, ...)
{
	time_t hora_actual;		// Hora actual del sistema
	struct tm * campos_hora;	// Hora actual descompuesta en campos
	va_list ap;			// Puntero a los parámetros variables
	int resultado;

	// Obtener la hora actual descompuesta en campos
	hora_actual = time(NULL);
	campos_hora = localtime(&hora_actual);

	// Mostrar la fecha y la hora en la que se emite el mensaje
	// de error. La fecha esta en formato yyyy-mm-dd hh:mm:ss
	fprintf(hLog, "%04d-%02d-%02d %02d:%02d:%02d (PID=%u) : ",
		campos_hora->tm_year + 1900, campos_hora->tm_mon + 1,
		campos_hora->tm_mday, campos_hora->tm_hour,
		campos_hora->tm_min, campos_hora->tm_sec,
		getpid());

	// Mostrar el mensaje de error en sí
	va_start(ap, s);
	resultado = vfprintf(hLog, s, ap);
	fflush(hLog);
	va_end(ap);

	errno = 0;
	return resultado;
}
