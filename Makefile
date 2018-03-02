OBJS = main.o
CC = gcc
DEBUG = -g
CFLAGS = -Wall -Werror -Wno-deprecated-declarations -I. -lssl -lcrypto -lpthread -c $(DEBUG)
LFLAGS = -lpthread -lcrypto -lssl

pbproxy : $(OBJS)
	$(CC) $(LFLAGS) $(OBJS) -o pbproxy $(LFLAGS)

main.o : main.h main.c
	$(CC) $(CFLAGS) main.c

clean :
	\rm -f *.o pbproxy *.tar.gz

sshd_server:
	@echo "Please enter key or keyfile. Leave blank for default"; \
	read skey; \
	if ["$$skey" -eq ""]; then \
		./pbproxy -l 2222 localhost 22; \
	else \
		./pbproxy -k $$skey -l 2222 localhost 22; \
	fi; \

sshd_local_client:
	@echo "Please enter key or keyfile. Leave blank for default"; \
	read ckey; \
	if ["$$ckey" -eq ""]; then \
		ssh -o "ProxyCommand ./pbproxy localhost 2222" localhost; \
	else \
		ssh -o "ProxyCommand ./pbproxy -k $$ckey localhost 2222" localhost; \
	fi; \

sshd_sbu_client:
	@echo "Please enter key or keyfile. Leave blank for default"; \
	read ckey; \
	if ["$$client_key" -eq ""]; then \
		ssh -o "ProxyCommand ./pbproxy vuln.cs.stonybrook.edu 2222" localhost; \
	else \
		ssh -o "ProxyCommand ./pbproxy -k $$ckey vuln.cs.stonybrook.edu 2222" localhost; \
	fi; \
	ssh -o "ProxyCommand ./pbproxy vuln.cs.stonybrook.edu 2222" localhost

tar:
	tar zcvf pbproxy.tar.gz main.c main.h Makefile pbproxy key.txt hw3.txt README
