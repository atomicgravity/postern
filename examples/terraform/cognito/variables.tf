variable "aws_region" {
  description = "AWS region for the Cognito user pool."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for sample resources."
  type        = string
  default     = "postern"
}

variable "managed_login_domain_prefix" {
  description = "Globally unique Cognito managed-login domain prefix."
  type        = string
}

variable "broker_url" {
  description = "Base URL of the Postern broker engineers will use."
  type        = string
}

variable "broker_resource" {
  description = "Cognito resource server identifier and OAuth resource value. Defaults to broker_url. The broker validates this as the access-token audience."
  type        = string
  default     = null

  validation {
    condition     = var.broker_resource == null || can(regex("^(https://|http://localhost(:[0-9]+)?(/|$)|[A-Za-z][A-Za-z0-9+.-]*://)", var.broker_resource))
    error_message = "broker_resource must start with https://, http://localhost, or a custom URI scheme."
  }
}

variable "loopback_ports" {
  description = "Postern loopback callback ports registered with the app client."
  type        = list(number)
  default     = [50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008, 50009, 50010]
}

variable "access_token_validity_minutes" {
  description = "Access token TTL."
  type        = number
  default     = 60
}

variable "id_token_validity_minutes" {
  description = "ID token TTL."
  type        = number
  default     = 60
}

variable "refresh_token_validity_days" {
  description = "Refresh token TTL."
  type        = number
  default     = 1
}