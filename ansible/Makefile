ANSIBLE_ARGS ?=

.PHONY: bootstrap syntax-check deploy

bootstrap:
	python3 -m venv .venv
	.venv/bin/pip install -r requirements.txt

syntax-check:
	ANSIBLE_HOME="$(CURDIR)/.ansible" .venv/bin/ansible-playbook --syntax-check deploy.yml

deploy:
	ANSIBLE_HOME="$(CURDIR)/.ansible" .venv/bin/ansible-playbook deploy.yml $(ANSIBLE_ARGS)
