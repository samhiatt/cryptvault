backend "consul" {
  address = "127.0.0.1:8500"
  path = "vault"
}

listener "tcp" {
  address = "127.0.0.1:8237"
  tls_disable = 1
}


disable_mlock = true