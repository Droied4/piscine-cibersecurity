NAME = ruby
DOCKER = docker
PATH = .
SHELL := /bin/sh

all:
	$(DOCKER) build --tag '$(NAME)' $(PATH)

clean:
	@echo cleaning container 
	$(DOCKER) rmi $(NAME)

fclean: clean

.PHONY: all clean fclean
