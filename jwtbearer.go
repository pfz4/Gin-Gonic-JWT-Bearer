package jwtbearer

type JwtBearer struct {
	Issuer *Issuer
	Audience string
}