/**************************************************************************************************
 *  packet_engine.c
 *
 *  Description:  Framework for capturing packets from NFQUEUE for processing. 
 *
 *	Before you run this you need to direct packets to the NFQUEUE queue, for example :
 *		  # iptables -A INPUT -p tcp -j NFQUEUE --queue-num 10
 *		  # iptables -A INPUT -p udp -j NFQUEUE --queue-num 10
 *
 *		  These will direct all tcp or udp packets respectively.  Other iptable filters
 *		  can be crafted to redirect specfic packets to the queue.  If you dont redirect any
 *		  packets to the queue your program won't see any packets.
 *
 *  to remove the filter: # iptables --flush
 *
 *  Must execute as root: # ./packet_engine -q num
 **************************************************************************************************/

#include <errno.h>
// #include <libnetfilter_queue/libnetfilter_queue.h>
// #include <libnetfilter_queue/linux_nfnetlink_queue.h> /* aggiunto per mac */
#include <limits.h>
#include <linux/netfilter_ipv4.h>
#include <math.h>
#include <netdb.h>   // for getservbyname()
#include <pthread.h> // for multi-threads
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

// constants
// ---------
#define PE_VERSION "1.0"
#define BUFSIZE 65536
#define PAYLOADSIZE 21
#define IN 1
#define OUT 0

// priorita' del processo interceptor: quasi la massima
#define INTERCEPTOR_PRIORITY 98
// generazione numeri random
#define LCG_MULTIPLIER 16807.0
#define LCG_MODULUS 2147483647.0
#define MY_ADDITION 10E-6

#define SEC_IN_MCSEC 1000000L

struct Lista {
    struct timeval istante; // Momento in cui si deve eliminare dalla lista
                            // il pacchetto ed inoltrare il buffer
    unsigned char *buffer;  // Puntatore all'area di memoria in cui e' stato
                            // immagazzinato il pacchetto entrante
    int lmsg;               // Lunghezza del pacchetto

    struct nfqnl_msg_packet_hdr h; // header del messaggio nfqnl
    struct nfq_q_handle *qh;       // puntatore allo handle, non va allocato nulla

    struct Lista *next; // Puntatore alla prossima struttura
};

struct Lista *LISTAglob = NULL;

//-----------------------------------------------------------------------------
// prototypes
// ----------
short int netlink_loop(unsigned short int queuenum);
static int nfqueue_cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data);
void print_options(void);
void on_quit(void);
int calcolaDelay(struct timeval tmr, struct timeval ist, struct timeval *delay);

// functions for thread
// --------------------
// 1.
void *tcap_packet_function(void *threadarg) {
    printf("Thread: sniffing packet...started\n");
    netlink_loop(*(unsigned short int *)threadarg);
    pthread_exit(NULL);
}

// main function
// -------------
int main(int argc, char **argv) {
    int ret = 0;
    unsigned short int queuenum = 0; // queue number to read
    int daemonized = 0;              // for background program

    // check parameters
    // ----------------
    if (argc < 1) {
        print_options();
        exit(-1);
    }

    // check root user ?
    // -----------------
    if (getuid() != 0) {
        fprintf(stderr, "\nPacket_engine Version %s\n", PE_VERSION);
        fprintf(stderr, "Copyright (c) NGO Quang Minh\n\n");
        fprintf(stderr, "This program can be run only by the system administrator\n\n");
        exit(-1);
    }

    // register a function to be called at normal program termination
    // --------------------------------------------------------------
    ret = atexit(on_quit);
    if (ret) {
        fprintf(stderr, "Cannot register exit function, terminating.\n");
        exit(-1);
    }

    // parse command line
    // ------------------
    int done = 0;
    while (!done) { //scan command line options
        ret = getopt(argc, argv, ":hq:B:");
        switch (ret) {
        case -1:
            done = 1;
            break;
        case 'h':
            print_options();
            exit(-1);
        case 'q':
            queuenum = (unsigned short int)atoi(optarg);
            break;
        case 'B':
            daemonized = 1;
            break;
        case '?': // unknown option
            fprintf(stderr,
                    "\nInvalid option or missing parameter, use packet_engine -h for help\n\n");
            exit(-1);
        }
    }

    // check if program run in background ?
    // ------------------------------------
    if (daemonized) {
        switch (fork()) {
        case 0: /* child */
            setsid();
            freopen("/dev/null", "w", stdout); /* redirect std output */
            freopen("/dev/null", "r", stdin);  /* redirect std input */
            freopen("/dev/null", "w", stderr); /* redirect std error */
            break;
        case -1: /* error */
            fprintf(stderr, "\nFork error, the program cannot run in background\n\n");
            exit(1);
        default: /* parent */
            exit(0);
        }
    }

    // begin with netfilter & write log file
    // -------------------------------------
    pthread_t tcap_packet, twrite_log;

    ret = pthread_create(&tcap_packet, NULL, tcap_packet_function,
                         (void *)&queuenum);
    if (ret) {
        printf("ERROR; return code from pthread_create() is %d\n", ret);
        exit(-1);
    }

    pthread_exit(NULL);
}

void init_myrandom(double *pseed, double initseed) {
    *pseed = initseed;
}

double myrandom_0_MAX(double max, double *pseed) {
    *pseed = (double)fmod((LCG_MULTIPLIER * (fabs(*pseed) + MY_ADDITION)), LCG_MODULUS);
    return (((*pseed) / LCG_MODULUS) * max);
}

double myrandom_0_1(double *pseed) {
    return (myrandom_0_MAX((double)1.0, pseed));
}

//---------------------------------------------------------------------

//------------------------------------------------------------------------
//Controlla che sia effettivamente stata allocata dinamicamente la memoria durante una malloc
void *Malloc(size_t size) {
    void *ptr;
    ptr = malloc(size);
    fflush(stdout);
    if (!ptr) {
        fprintf(stderr, "Errore di allocazione memoria\n");
        fflush(stdout);
        exit(1);
    } else
        return (ptr);
}

//----------------------------------------------------------
//*****************  CALCOLATEMPO *************************
//calcolaTempo serve ad intercept per decidere se usare la select come un timer oppure saltarla con npronti
//pacchetti perchè il ritardo con cui dovrebbero partire è minore del tempo per eseguire la select stessa.
//Chiamata come: "calcolaTempo(timer2,lista,&delay);"
//"tmr" è il tempo attuale(ritornato da una gettimeofday)
//"plista" è un puntatore alla struttura lista
//"delay" contiene il ritardo del pacchetto che deve aspettare la select
//"return" ritorna il numero dei pacchetti pronti a saltare la select
//---------------------------------------------------------------
int calcolaTempo(struct timeval tmr, struct Lista *plista, struct timeval *delay) {

// scaccia aveva messo 0
// #define timeselect 0 i				//3000	//7000 //tempo per eseguire una select
#define timeselect 0 //3000	//7000 //tempo per eseguire una select

    int npronti = 0, bool = 1;

    calcolaDelay(tmr, plista->istante, delay); //Calcola il delay tra l'istante attuale ed il pacchetto n-esimo
    //Se il pacchetto deve partire in un intorno di tempo di lunghezza timeselect
    while (
        (
            (*delay).tv_sec == 0) &&
        ((*delay).tv_usec < timeselect) &&
        bool) {
        npronti++;
        if (plista->next != NULL) { //Ci sono ancora pacchetti nella coda
            plista = plista->next;
            calcolaDelay(tmr, plista->istante, delay);
        } else
            bool = 0;
    }
    //printf("CALCOLATEMPO npronti %d\n",npronti);
    return npronti;
}

//----------------------------------------------------------------------
//***************  CALCOLADELAY  *********************************
//calcolaDelay serve alla select per spedire pacchetti al momento giusto; scrive su delay il ritardo.
//Chiamata come: calcolaDelay(tmr,plista->istante,delay); (da dentro calcolaTempo)
//"tmr" = tempo attuale
//"ist" = tempo in cui dovrebbe partire il primo della lista
//"delay" ritardo che deve aspettare la select
//------------------------------------------------------------------------
int calcolaDelay(struct timeval tmr, struct timeval ist, struct timeval *delay) {

    (*delay).tv_sec = ist.tv_sec - tmr.tv_sec; //Sottraggo i secondi tra di loro
    if ((*delay).tv_sec < 0) {                 //intercept è in ritardo
        //printf("+++INTERCEPT IN RITARDO SEC%ld \n",(*delay).tv_sec); //cancellare!!!!
        (*delay).tv_sec = 0;
        (*delay).tv_usec = 0;
        //printf("Sono in ritardo x sec ==> svuoto\n");
        //exit(1);//cancellare!!!!
    } else {
        (*delay).tv_usec = ist.tv_usec - tmr.tv_usec;
        if ((*delay).tv_usec < 0) { //Se non è zero
            if ((*delay).tv_sec > 0) {
                //Devo scalare di uno i secondi e sottrarli ai micro secondi ossia aggiungo 1000000 all'ultima espressione
                (*delay).tv_sec = (*delay).tv_sec - 1;
                (*delay).tv_usec = (ist.tv_usec) - tmr.tv_usec + SEC_IN_MCSEC;
            } else {
                //printf("+++INTERCEPT IN RITARDO USEC%ld \n",(*delay).tv_usec);  //cancellare!!!!!!!!
                (*delay).tv_usec = 0;
                //printf("Sono in ritardo x mcsec ==> svuoto\n");
                // exit(1); //cancellare!!!!!!!!!!!!
            }
        }
    }
    //printf("calcolaDelay:.... ritardo(sec)=%ld ........ ritardo(usec)=%ld\n",(*delay).tv_sec,(*delay).tv_usec);
    return 1;
}

int stampalista(struct Lista *plista) {
    int num = 0;
    struct Lista *p = plista;
    printf("lista: ");
    while (p != NULL) {
        num++;
        printf("%d ", p->lmsg);
        p = p->next;
    }
    printf("bytes \n");
    fflush(stdout);
    return num;
}

//--------------------------------------------------------------------
static void inLista(struct Lista **clista, struct timeval tmist, unsigned char *pbuff, int lmsg, struct nfqnl_msg_packet_hdr *ph, struct nfq_q_handle *qh) {
    struct Lista *appo, *padre, *figlio, *nonno = NULL;
    struct timeval tconf;
    struct Lista *pnewnodo;

    //printf("CREAZIONE NUOVO NODO DELLA LISTA\n");
    //alloco lo spazio per contenere il nuovo nodo  della lista
    pnewnodo = (struct Lista *)Malloc(sizeof(struct Lista));

    //setto l'istante in cui dovrebbe essere inoltrato il pacchetto
    pnewnodo->istante.tv_sec = tmist.tv_sec;
    pnewnodo->istante.tv_usec = tmist.tv_usec;

    //Alloco lo spazio per contenere il pacchetto da spedire
    pnewnodo->buffer = (unsigned char *)Malloc(lmsg);

    //Copio nello spazio allocato bufpacket
    memcpy(pnewnodo->buffer, pbuff, lmsg);

    //Copio il contenuto di  nfqnl header
    memcpy(&(pnewnodo->h), ph, sizeof(struct nfqnl_msg_packet_hdr));

    //Copio PUNTATORE all'handle
    pnewnodo->qh = qh;

    pnewnodo->lmsg = lmsg; // Inserisco la lunghezza di bufpacket
    pnewnodo->next = NULL; // Punto al prossimo (essendo il primo!)

    if (*clista == NULL) { // PRIMO ELEMENTO DELLA LISTA
                           //printf("CREAZIONE DELLA LISTA\n");

        (*clista) = pnewnodo;
    } else {

        //INSERIMENTO IN ORDINE DI ISTANTE DI SPEDIZIONE
        padre = *clista;          //Mi preparo a scorrere la lista
        figlio = (*clista)->next; //setto i tempi di confronto
        //trova il minore minimo di tmist nella lista
        tconf.tv_sec = (padre)->istante.tv_sec; //meglio tconf = (padre)->istante;
        tconf.tv_usec = (padre)->istante.tv_usec;
        //se deve essere il primo della lista (INSERIMENTO IN TESTA)

        if ((tconf.tv_sec > tmist.tv_sec) || ((tconf.tv_sec == tmist.tv_sec) && (tconf.tv_usec > tmist.tv_usec))) {
            //printf("INSERIMENTO IN TESTA\n");
            pnewnodo->next = padre; //Punto al prossimo (essendo il primo!)
            *clista = pnewnodo;     //Collego la nuova struttura creata alla lista
            pnewnodo = NULL;
            padre = NULL;
            //printf("INLISTA :...........N°accodati= %d\n",j);
        } else { //dal secondo in poi (INSERIMENTO IN MEZZO)

            //printf("INSERIMENTO IN MEZZO\n");
            while (((tconf.tv_sec < tmist.tv_sec) || ((tconf.tv_sec == tmist.tv_sec) && (tconf.tv_usec <= tmist.tv_usec))) && (padre != NULL)) {
                //Percorro la lista
                nonno = padre;
                padre = figlio;
                if (figlio != NULL)
                    figlio = figlio->next; //Non cerco di scendere ancora se sono alla fine
                if (padre != NULL) {       //Non cerco campi di una struttura che non esiste
                    tconf.tv_sec = padre->istante.tv_sec;
                    tconf.tv_usec = padre->istante.tv_usec;
                }
            }

            //Nel caso davanti all'ultimo letto
            nonno->next = pnewnodo;
            pnewnodo->next = padre;
            padre = NULL; // E' inutile padre è già NULL
            pnewnodo = NULL;
            //printf("INLISTA :...........N°accodati= %d\n",j);

        } //end else  (INSERIMENTO IN TESTA)
    }     //end else (*clista == NULL)
}

//----------------------------------------------------------------------------
static int head(struct Lista **clista, int *psize, unsigned char **ppbufsend, struct nfqnl_msg_packet_hdr *ph, struct nfq_q_handle **ppqh) {
    struct Lista *next, *primo;

    if (*clista == NULL)
        return (0);
    else {
        primo = *clista;                //Ottengo l'indirizzo del primo della lista
        next = (*clista)->next;         //Variabile di appoggio
        *ppbufsend = (*clista)->buffer; //Punta area memoria che contiene intero msg

        *ph = (*clista)->h;
        *ppqh = (*clista)->qh;

        (*clista)->buffer = NULL; //Per evitare che il gestore dell'area di memoria dinamica abbia alcuni dubbi
        *psize = (*clista)->lmsg; //Riottiene la lunghezza del msg
        *clista = next;           //Elimino dalla lista la testa
        primo->next = NULL;       //Per evitare che il gestore dell'area di memoria dinamica abbia alcuni dubbi
        free(primo);              //Dealloco quella memoria
        primo = NULL;
        next = NULL;
        return (1);
    }
}

static void spedisci(int size2, unsigned char **pfull_packet2, int u_verdict, struct nfqnl_msg_packet_hdr *h2, struct nfq_q_handle *qh2) {

    int rval;
    int id2 = 0;

    id2 = ntohl(h2->packet_id);

    rval = nfq_set_verdict(qh2, id2, NF_ACCEPT, size2, *pfull_packet2);
    if (rval < 0) {
        printf("Errore nfq_set_verdict %d\n", rval);
        perror("Errore :");
        // die(*handle);
    }
    free(*pfull_packet2);

    *pfull_packet2 = NULL;

    printf("nfq_set_verdict success - rval %d\n", rval);
    fflush(stdout);
}

// loop to process a received packet at the queue
// ----------------------------------------------
short int netlink_loop(unsigned short int queuenum) {
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd, maxfdp;
    char buf[BUFSIZE];
    fd_set fdr; //Per la select
    int user_verdict = NF_ACCEPT;
    int ricevuti = 0, spediti = 0, pronti = 0;

    LISTAglob = NULL;

    h = nfq_open();
    if (!h) {
        printf("Error during nfq_open()\n");
        exit(-1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0) {
        printf("Error during nfq_unbind_pf()\n");
        exit(-1);
    }

    fflush(stdout);

    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf failed: ");
        fflush(stderr);
        printf("Error during nfq_bind_pf()\n");
        exit(-1);
    }
    printf("NFQUEUE: binding to queue '%hd'\n", queuenum);

    // create queue
    qh = nfq_create_queue(h, queuenum, &nfqueue_cb, NULL);
    if (!qh) {
        printf("Error during nfq_create_queue()\n");
        exit(-1);
    }

    // sets the amount of data to be copied to userspace for each packet queued
    // to the given queue.
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        printf("Can't set packet_copy mode\n");
        exit(-1);
    }

    nh = nfq_nfnlh(h);
    fd = nfnl_fd(nh);

    while (1) {

        int ready;

    STRONZO:
        // fflush(stderr);

    try_again:
        if (LISTAglob == NULL) // nessun pacchetto in lista per spedizione
        {
            maxfdp = fd + 1;
            FD_ZERO(&fdr);
            FD_SET(fd, &fdr);
            ready = select(maxfdp, &fdr, NULL, NULL, NULL); //SELECT
                                                            //printf("Lista NULL --> esco dopo select\n");
        } else {
            struct timeval timer2, delay;

            ready = gettimeofday(&timer2, NULL); //scrivo su timer2 l'istante attuale

            // calcolaTempo serve ad intercept per decidere
            // se usare la select come un timer oppure saltarla
            // con npronti pacchetti perchè il ritardo con cui dovrebbero
            // timer2 = tempo attuale
            //lista = puntatore al primo della lista
            //delay = ritardo che deve aspettare la select

            pronti = calcolaTempo(timer2, LISTAglob, &delay);
            //la select funziona da timer

            if (pronti == 0) {
                maxfdp = fd + 1;
                FD_ZERO(&fdr);
                FD_SET(fd, &fdr);
                ready = select(maxfdp, &fdr, NULL, NULL, &delay);
                pronti = 1; // Perche' altrimenti non entra nel while(pronti>0)
            } else {        //Entra nel ramo del flusso del programma che spedisce
                if (pronti > 0) {
                    ready = 0;
                    //printf("Sono in ritardo ==> svuoto; pronti: %d\n",pronti);
                } else
                    printf("Errore in calcola tempo pronti=%d\n", pronti);
            }
        }

        // Cosa succede chiamando ipq_read --> ipq_netlink_recvfrom(h, buf, len);
        // ----> recvfrom(h->fd, buf, len, 0, (struct sockaddr *)&h->peer, &addrlen)
        // # in buf ci dovrebbe essere il pkt letto
        // # recvfrom restituisce il numero di byte letti

        if (ready > 0) {
            if (FD_ISSET(fd, &fdr)) {
                int rval;
                // printf("attesa per read\n");
                do {
                    rval = recv(fd, buf, sizeof(buf), 0);
                } while ((rval < 0) && (errno == EINTR));

                if (rval < 0) {
                    printf("netlink: recv failed - TERMINO!!!!\n");
                    exit(1);
                } else if (rval == 0) {
                    printf("netlink: recv read packet EMPTY rval==0 - CONTINUO!\n");
                } else { // rval>0
                    printf("\n ------- received %d bytes ----------\n", rval);
                    // triggers an associated callback
                    // for the given packet received from the queue.

                    printf("prima di nfq_handle\n");
                    fflush(stdout);
                    // INVOCA LA FUNZIONE nfqueue_cb   stabilita con la chiamata nfq_create_queue(h,  queuenum, &nfqueue_cb, NULL);
                    nfq_handle_packet(h, buf, rval);
                    printf("dopo nfq_handle\n");
                    fflush(stdout);
                }
            }
        }

        else if (ready == 0) { // Svuoto eventualmente la coda.
            // NB questo ciclo deve essere eseguito almeno una volta
            while (pronti > 0) {
                int found_addresses = 0;
                struct nfqnl_msg_packet_hdr h2;
                unsigned char *full_packet2; // data of packet (payload)
                struct nfq_q_handle *qh2;
                int size2, ris;

                printf("pronti >0 prima di head  qh2 %p\n", qh2);

                pronti--;
                // PACCHETTO PRONTO PER ESSERE SPEDITO (scaduto il timeout)
                // - head estrae la prima struttura della lista,
                //   facendo partire la lista dalla seconda struttura
                // - alloca lo spazio necessario puntato da full_packet2 e ph2,
                // - non alloca lo spazio puntato da qh2 ma ne cambia solo l'indirizzo,
                // - modifica il valore di size2 mettendovi la dimensione
                //   del pacchetto a cui viene fatto puntare full_packet2,
                // - rilascia la memoria dell'elemento eliminato da lista
                ris = head(&LISTAglob, &size2, &full_packet2, &h2, &qh2);

                if ((ris <= 0) || (qh2 == NULL)) {
                    printf("PORC!!!   NFQUEUE: can't get msg packet "
                           "ris %d handle qh2 %p\n",
                           ris, qh2);
                } else if (size2 <= 0) {
                    printf("PORC!!! strano, pkt VUOTO size %d \n", size2);
                } else {

                    int id2 = 0, id_protocol2;

                    id2 = ntohl(h2.packet_id);
                    printf("size %d hw_protocol = 0x%04x hook = %u id = %u \n",
                           size2, ntohs(h2.hw_protocol), h2.hook, id2);
                    id_protocol2 = identify_ip_protocol(full_packet2);

                    printf("Packet from %s", get_src_ip_str(full_packet2));
                    printf(" to %s\n", get_dst_ip_str(full_packet2));
                    fflush(stdout);

                    switch (h2.hook) {
                    case NF_IP_LOCAL_IN: // packets IN
                        switch (id_protocol2) {
                        case IPPROTO_ICMP:
                            printf("IN ICMP - no Port\n");
                            fflush(stdout);
                            break;
                        case IPPROTO_TCP:
                            printf("IN SRC Port: %d\n", get_tcp_src_port(full_packet2));
                            printf("IN DST Port: %d\n", get_tcp_dst_port(full_packet2));
                            break;
                        case IPPROTO_UDP:
                            printf("IN SRC Port: %d\n", get_udp_src_port(full_packet2));
                            printf("IN DST Port: %d\n", get_tcp_dst_port(full_packet2));
                            break;
                        case IPPROTO_ESP:
                            break;
                        default:
                            break;
                        }
                        break;
                    case NF_IP_LOCAL_OUT: // packets OUT
                        switch (id_protocol2) {
                        case IPPROTO_ICMP:
                            printf("OUT ICMP - no Port\n");
                            fflush(stdout);
                            break;
                        case IPPROTO_TCP:
                            printf("OUT SRC Port: %d\n", get_tcp_src_port(full_packet2));
                            printf("OUT DST Port: %d\n", get_tcp_dst_port(full_packet2));
                            break;
                        case IPPROTO_UDP:
                            //num_pkt_protocol[2].out++;
                            printf("OUT SRC Port: %d\n", get_udp_src_port(full_packet2));
                            printf("OUT DST Port: %d\n", get_tcp_dst_port(full_packet2));
                            break;
                        case IPPROTO_ESP:
                            break;
                        default:
                            break;
                        }
                        break;
                    default: // Ignore the rest (like: FORWARD, )
                        break;
                    }

                    spedisci(size2, &full_packet2, user_verdict, &h2, qh2); //free full_packet2

                    spediti++;

#ifdef OUTPUT
                    printf("........ spedito pacchetto= %d\n", spediti);
#endif
#ifdef OUTPUT
                    if (found_addresses) {
                        printf("spedito sorg %s dest %s \n", sorg, dest);
                        fflush(stdout);
                    }
#endif
                } // end: else

            } // end: while (pronti>0)

        } //end: if(ready == 0)

        else { // Caso in cui (ready < 0)
               //gestione dell'errore della select
            perror("select error :");
        }

    } //end:while(1)

    // unbinding before exit
    printf("NFQUEUE: unbinding from queue '%hd'\n", queuenum);
    nfq_destroy_queue(qh);
    nfq_close(h);
    return (0);
}

int macaddress2ascii(char *strmacaddress, int len, uint8_t *macaddr) {

    int i = 0;

    strmacaddress[0] = '\0';
    for (i = 0; i < 6; i++) {

        sprintf(strmacaddress + strlen(strmacaddress), "%02X", macaddr[i]);
        if (i < 5)
            strcat(strmacaddress, ".");
    }
    return (1);
}

#if 0
/* pointer to a nlif interface resolving handle */
struct nlif_handle *fetch_interface_table(void) {
	struct nlif_handle *h;
	h = nlif_open();
	if (h == NULL) {
		perror("nlif_open");
	fflush(stderr);
		return(NULL);
	}
	nlif_query(h);

	printf("fine fetch_interface_table\n");
	fflush(stdout);
	return(h);
}


int get_indev_name(struct nfq_data *nfq_pkt, char indevname[]) {

		char porc[128];

		struct nlif_handle *nlif_h;  /* pointer to a nlif interface resolving handle */
		int ret=0;

		nlif_h=fetch_interface_table();
		if(nlif_h==NULL) return(0);

		if( nfq_get_indev_name(nfq_pkt, nlif_h, indevname) > 0 ) 
			ret=1;

		printf("fine nfq_get_indev_name\n");
		fflush(stdout);

		nlif_close(nlif_h);
		return(ret);
}

int get_outdev_name(struct nfq_data *nfq_pkt, char indevname[]) {

		struct nlif_handle *nlif_h;  /* pointer to a nlif interface resolving handle */
		int ret=0;

		nlif_h=fetch_interface_table();
		if(nlif_h==NULL) return(0);
		if( nfq_get_outdev_name(nfq_pkt, nlif_h, indevname) > 0 ) 
			ret=1;

		printf("fine nfq_get_outdev_name\n");
		fflush(stdout);

		nlif_close(nlif_h);
		return(ret);
}
#endif

// function callback for packet processing
// ---------------------------------------
static int nfqueue_cb(
    struct nfq_q_handle *qh, /* qh va salvato in inLista */
    struct nfgenmsg *nfmsg,
    struct nfq_data *nfq_pkt, /* era nfa -> cambiato in nfq_pkt */
    void *data) {

    struct nfqnl_msg_packet_hdr *ph;
    ph = nfq_get_msg_packet_hdr(nfq_pkt);

    printf("inizio nfqueue_cb qh %p\n", qh);
    fflush(stdout);

    if (ph) {
        int id = 0, size = 0;
        unsigned char *full_packet; // get data of packet (payload)
        struct timeval timeist;
        long int msecdelay = 1000L;

        struct nfqnl_msg_packet_hw *macAddr; /*  aggiunto */
        struct timeval tv;                   /*  aggiunto */
        char indevname[256], outdevname[256];

        id = ntohl(ph->packet_id);
        printf("hw_protocol = 0x%04x hook = %u id = %u \n",
               ntohs(ph->hw_protocol), ph->hook, id);

        /* HEADER DATALINK - aggiunto */

        // The HW address is only fetchable at certain hook points
        // and it is the source address
        macAddr = nfq_get_packet_hw(nfq_pkt);
        if (macAddr) {

            char strmacaddress[100];
            macaddress2ascii(strmacaddress, macAddr->hw_addrlen, macAddr->hw_addr);
            printf("mac hw_len %i \"%s\"\n", ntohs(macAddr->hw_addrlen), strmacaddress);
            // end if macAddr
        } else {
            printf("no MAC addr\n");
        }

#if 0
		/* get name of the indev */
		if( get_indev_name(nfq_pkt, indevname) ) 
			printf("indev_name %s\n", indevname);
		else
			printf("indev_name not available\n");
		fflush(stdout);

		/* get name of the outdev */
		if( get_outdev_name(nfq_pkt, outdevname) ) 
			printf("outdev_name %s\n", outdevname);
		else
			printf("outdev_name not available\n");
		fflush(stdout);
#endif

        /* altre informazioni accessorie */

        if (!nfq_get_timestamp(nfq_pkt, &tv)) {
            printf("tstamp %i sec %i usec\n", (int)tv.tv_sec, (int)tv.tv_usec);
        } else {
            printf("no tstamp\n");
        }

        printf("mark %d\n", nfq_get_nfmark(nfq_pkt));

        // Note that you can also get the physical devices
        printf(" %d\n", nfq_get_indev(nfq_pkt));
        printf(" %d\n", nfq_get_outdev(nfq_pkt));

        /* fine aggiunto per livello datalink */

        /* ottengo l'indirizzo full_packet del pacchetto dati 
		 * da salvare in inLista per eventuali modifiche 
		 * e da usare per la set_verdict
		 */
        size = nfq_get_payload(nfq_pkt, &full_packet);

        printf("nfq_pkt %p   data %p   size %d full_packet %p  nfq_pkt-full_packet %d\n",
               nfq_pkt, data, size, full_packet, ((char *)nfq_pkt) - ((char *)full_packet));
        fflush(stdout);

        if (data == NULL)
            printf("data NULL\n");
        fflush(stdout);

        /* ottengo l'identificatore del pacchetto dati 
		 * da salvare in inLista e da usare per la set_verdict
		 */
        int id_protocol = identify_ip_protocol(full_packet);
        printf("Packet from %s", get_src_ip_str(full_packet));
        printf(" to %s\n", get_dst_ip_str(full_packet));
        fflush(stdout);

        /* 
		NON SPEDISCO SUBITO MA METTO IN CODA
		// let the packet continue on.  NF_ACCEPT will pass the packet
		// -----------------------------------------------------------
		nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
		*/

        if ((id_protocol != IPPROTO_ICMP) &&
            (id_protocol != IPPROTO_TCP) &&
            (id_protocol != IPPROTO_UDP)) {
            // let the packet continue on.  NF_ACCEPT will pass the packet
            // -----------------------------------------------------------
            printf("SPEDISCO SUBITO SENZA ACCODARE\n");
            fflush(stdout);

            nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

        } else {

            // procedo a mettere in coda

            // setto istante di spedizione del pkt
            // aggiungendo un ritardo all'istante attuale
            gettimeofday(&timeist, NULL);
            timeist.tv_usec += msecdelay * 1000L;

            printf("prima di inLista qh %p ritardo aggiunto msecdelay=%ld  timeval %ld sec %ld msec\n", qh, (long)msecdelay, (long)timeist.tv_sec, (long)timeist.tv_usec);
            fflush(stdout);

            inLista(&LISTAglob, timeist, full_packet, size, ph, qh);

            printf("dopo inLista qh %p\n", qh);
            fflush(stdout);
        }
    } else {
        printf("PORC!!! NFQUEUE: can't get msg packet header.\n");

        /*
		printf("fine nfqueue_cb  sleep 2 prima di restituisce 1\n"); fflush(stdout);
		sleep(2);
		*/

        printf("fine nfqueue_cb  restituisce 1\n");
        fflush(stdout);

        return (1); // from nfqueue source: 0 = ok, >0 = soft error, <0 hard error
    }

    printf("fine nfqueue_cb  restituisce 0\n");
    fflush(stdout);

    return (0);
}

/*
 * this function displays usages of the program
 */
void print_options(void) {
    printf("\nPacket_engine %s created by NQ.Minh", PE_VERSION);
    printf("\n\nSyntax: packet_engine [ -h ] [ -q queue-num] [ -l logfile ] [ -B ]\n\n");
    printf("  -h\t\t- display this help and exit\n");
    printf("  -q <0-65535>\t- listen to the NFQUEUE (as specified in --queue-num with iptables)\n");
    //	printf("  -l <logfile>\t- allow to specify an alternate log file\n");
    printf("  -B\t\t- run this program in background.\n\n");
}

/*
 * this function is executed at the end of program
 */
void on_quit(void) {
    printf("Program termined!\n");
}
