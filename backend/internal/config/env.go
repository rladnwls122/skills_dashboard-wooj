package config

// Typed getters over Settings, mirroring the ENV object in
// src/lib/server/config.ts. Getters, not frozen values: the settings screen
// writes overrides to SQLite and they take effect on the next request.

func (s *Settings) Region() string         { return s.Value("AWS_REGION") }
func (s *Settings) WafWebAclName() string  { return s.Value("WAF_WEB_ACL_NAME") }
func (s *Settings) AlbName() string        { return s.Value("ALB_NAME") }
func (s *Settings) EksClusterName() string { return s.Value("EKS_CLUSTER_NAME") }
func (s *Settings) RdsProxyName() string   { return s.Value("RDS_PROXY_NAME") }
func (s *Settings) WafLogGroup() string    { return s.Value("WAF_LOG_GROUP") }
func (s *Settings) AppLogGroup() string    { return s.Value("APP_LOG_GROUP") }
func (s *Settings) TargetNamespace() string {
	return s.Value("TARGET_NAMESPACE")
}

func (s *Settings) WafScope() string {
	if s.Value("WAF_SCOPE") == "REGIONAL" {
		return "REGIONAL"
	}
	return "CLOUDFRONT"
}

// WafRegion: WAF metrics/API for CLOUDFRONT scope live in us-east-1 only.
func (s *Settings) WafRegion() string {
	if s.WafScope() == "CLOUDFRONT" {
		return "us-east-1"
	}
	return s.Region()
}
