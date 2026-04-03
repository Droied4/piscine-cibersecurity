NAME 	= inquisitor 
DOCKER = docker
RUN = $(DOCKER) run
COMPOSE = $(DOCKER) compose

# ╔══════════════════════════════════════════════════════════════════════════╗ #  
#                               SOURCES                                        #
# ╚══════════════════════════════════════════════════════════════════════════╝ # 

MANDATORY_PATH = -f ./compose.yml

# ╔══════════════════════════════════════════════════════════════════════════╗ #  
#                               RULES                                          #
# ╚══════════════════════════════════════════════════════════════════════════╝ # 

up: 
	@$(COMPOSE) $(MANDATORY_PATH) $@ --build -d

setup:
	cp ./srcs/.env.sample srcs/.env

it:
	@$(DOCKER) exec -it $(ID) sh

clean: images
	@echo
	@$(COMPOSE) $(MANDATORY_PATH) down
	@printf "$(RED)Removing images above$(NC)\n"
	@$(DOCKER) container prune -f && $(DOCKER) image prune -a -f
	@printf "$(GREEN) $@ COMPLETE! $(NC)\n"

fclean: clean images
	@echo
	@echo "Starting full clean"
	@$(DOCKER) system prune -a
	@echo
	@printf "$(GREEN)COMPLETE! $(NC)\n"

logs:
	@$(DOCKER) $@ $(ID)

ps:
	@$(DOCKER) $@ -a

images:
	@$(DOCKER) $@

re: fclean up

.PHONY: up setup it clean down logs ps images re
