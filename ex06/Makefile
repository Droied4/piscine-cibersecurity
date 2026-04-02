NAME = inquisitor
DOCKER = docker
PATH_DOCKERFILE = .
SHELL := /bin/sh

all: build run

build:
	$(DOCKER) build --tag '$(NAME)' $(PATH_DOCKERFILE)

run:
	@if [ ! $$(docker ps -a -q -f name=^$(NAME)$$) ]; then \
		echo "Creating container $(NAME)"; \
		$(DOCKER) run -d --name $(NAME) $(NAME); \
	else \
		echo "The container '$(NAME)' already exists. Skipping step..."; \
	fi

clean:
	@echo cleaning container 
	$(DOCKER) image prune
	$(DOCKER) stop $(NAME)
	$(DOCKER) rm $(NAME)

fclean: clean
	$(DOCKER) image prune -a

re: fclean all

.PHONY: all clean fclean re
