# Preserve existing cloud resources while their Terraform addresses move into
# the local security module.
moved {
  from = yandex_vpc_default_security_group.default
  to   = module.security.yandex_vpc_default_security_group.default
}

moved {
  from = yandex_vpc_security_group.alb
  to   = module.security.yandex_vpc_security_group.alb
}

moved {
  from = yandex_vpc_security_group.backend
  to   = module.security.yandex_vpc_security_group.backend
}

moved {
  from = data.yandex_sws_waf_rule_set_descriptor.owasp
  to   = module.security.data.yandex_sws_waf_rule_set_descriptor.owasp
}

moved {
  from = yandex_logging_group.sws
  to   = module.security.yandex_logging_group.sws
}

moved {
  from = yandex_sws_waf_profile.test
  to   = module.security.yandex_sws_waf_profile.test
}

moved {
  from = yandex_sws_security_profile.test
  to   = module.security.yandex_sws_security_profile.test
}
