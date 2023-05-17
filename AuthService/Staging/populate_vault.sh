#!/bin/bash

export VAULT_ADDR='http://vault:8200'
export VAULT_TOKEN='00000000-0000-0000-0000-000000000000'

vault kv put secret/enviromentVariables secret=kerrik123456789123456789123456789 issuer=authservice123456789123456789