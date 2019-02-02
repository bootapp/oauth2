package generates

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/wangh09/oauth2"
	"github.com/wangh09/oauth2/errors"
	"github.com/wangh09/oauth2/models"
	"github.com/wangh09/oauth2/utils/uuid"
	"strings"
	"time"
)

// JWTAccessClaims jwt claims
type JWTAccessClaims struct {
	Aud []string `json:"aud,omitempty"`
	Iat int64 `json:"iat,omitempty"`
	UserID    string `json:"user_id,omitempty"`
	Scope string `json:"scope,omitempty"`
	Authorities []string `json:"authorities,omitempty"`
	Ati string `json:"ati,omitempty"`
	Jti string `json:"jti,omitempty"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
}

// Valid claims verification
func (a *JWTAccessClaims) Valid() error {
	if time.Unix(a.ExpiresAt, 0).Before(time.Now()) {
		return errors.ErrInvalidAccessToken
	}
	return nil
}

func NewJWTAccessDecoder(pubKeyPem []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	ag := &JWTAccessGenerate{
	}
	err := ag.UpdatePublicKey(pubKeyPem, method)
	if err != nil {
		return nil
	}
	return ag
}

// NewJWTAccessGenerate create to generate the jwt access token instance
func NewJWTAccessGenerate(key []byte, method jwt.SigningMethod) *JWTAccessGenerate {
	ag := &JWTAccessGenerate{}
	err :=ag.UpdatePrivateKey(key, method)
	if err != nil {
		return nil
	}
	return ag
}

// JWTAccessGenerate generate the jwt access token
type JWTAccessGenerate struct {
	SignedKey    []byte
	SignedMethod jwt.SigningMethod
	SigningKey    interface{}
	PublicKey    interface{}
}

func (ag *JWTAccessGenerate) UpdatePrivateKey(key []byte, method jwt.SigningMethod) error {
	ag.SignedKey = key
	ag.SignedMethod = method
	if ag.isEs() {
		privateKey, err := jwt.ParseECPrivateKeyFromPEM(ag.SignedKey)
		if err != nil {
			return err
		}
		ag.SigningKey = privateKey
		ag.PublicKey = privateKey.PublicKey
	} else if ag.isRsOrPS() {
		privKey, err := jwt.ParseRSAPrivateKeyFromPEM(key)
		if err != nil {
			return err
		}
		ag.SigningKey = privKey
		ag.PublicKey = privKey.Public()
	} else if ag.isHs() {
		ag.SigningKey = ag.SignedKey
	} else {
		return errors.ErrInvalidGrant
	}
	return nil
}

func (ag *JWTAccessGenerate) UpdatePublicKey(key []byte, method jwt.SigningMethod) error {
	ag.SignedMethod = method
	if ag.isEs() {
		publicKey, err := jwt.ParseECPublicKeyFromPEM(key)
		if err != nil {
			return err
		}
		ag.PublicKey = publicKey
	} else if ag.isRsOrPS() {
		publicKey, err := jwt.ParseRSAPublicKeyFromPEM(key)
		if err != nil {
			return err
		}
		ag.PublicKey = publicKey
	} else if ag.isHs() {
		ag.SigningKey = key
	} else {
		return errors.ErrInvalidGrant
	}
	return nil
}
// Token based on the UUID generated token
func (a *JWTAccessGenerate) encode(claims *JWTAccessClaims) (signedToken string, err error) {
	if a.SignedMethod == nil {
		return "", fmt.Errorf("JWTAccessGenerate: Invalid signing method.")
	}
	token := jwt.NewWithClaims(a.SignedMethod, claims)
	signedToken, err = token.SignedString(a.SigningKey)
	return signedToken, err
}
func (a *JWTAccessGenerate) decode(signedToken string) (claims *JWTAccessClaims, err error) {
	token, err := jwt.ParseWithClaims(signedToken, &JWTAccessClaims{}, func(token * jwt.Token) (interface{}, error) {
		if token.Method.Alg() == a.SignedMethod.Alg() {
			if a.isEs() || a.isRsOrPS() {
				return a.PublicKey, nil
			} else if a.isHs() {
				return a.SignedKey, nil
			}
		}
		return nil, errors.ErrInvalidAccessToken
	})
	if err != nil {
		return nil, errors.ErrInvalidAccessToken
	}
	if claims, ok := token.Claims.(*JWTAccessClaims); ok && token.Valid {
		return claims, nil
	} else {
		return nil, errors.ErrInvalidAccessToken
	}
}

func (a *JWTAccessGenerate) ExtractInfo(signedToken string) (ti oauth2.TokenInfo, err error) {
	claims, err := a.decode(signedToken)
	if err != nil {
		return
	}
	if err = claims.Valid(); err != nil {
		return
	}
	iat := time.Unix(claims.Iat, 0)
	ti = models.NewToken()
	ti.SetClientID(claims.ClientID)
	ti.SetUserID(claims.UserID)
	ti.SetScope(claims.Scope)
	ti.SetAccessCreateAt(iat)
	ti.SetRefreshCreateAt(iat)
	ti.SetAuthorities(claims.Authorities)
	ti.SetExpiresAt(time.Unix(claims.ExpiresAt,0))
	return
}
func (a *JWTAccessGenerate) Token(data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	tokenID := uuid.Must(uuid.NewRandom()).String()
	claims := &JWTAccessClaims{
		Aud: []string{"user"},
		Iat: data.TokenInfo.GetAccessCreateAt().Unix(),
		UserID:    data.UserID,
		Scope: "user_rw",
		Authorities: data.TokenInfo.GetAuthorities(),
		Jti: tokenID,
		ClientID:  data.Client.GetID(),
		ExpiresAt: data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetAccessExpiresIn()).Unix(),
	}
	access, err = a.encode(claims)

	if err != nil {
		return
	}

	if isGenRefresh {
		claims.Ati = tokenID
		claims.Jti = uuid.Must(uuid.NewRandom()).String()
		claims.ExpiresAt = data.TokenInfo.GetAccessCreateAt().Add(data.TokenInfo.GetRefreshExpiresIn()).Unix()
		refresh, err = a.encode(claims)
	}

	return
}

func (a *JWTAccessGenerate) isEs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "ES")
}

func (a *JWTAccessGenerate) isRsOrPS() bool {
	isRs := strings.HasPrefix(a.SignedMethod.Alg(), "RS")
	isPs := strings.HasPrefix(a.SignedMethod.Alg(), "PS")
	return isRs || isPs
}

func (a *JWTAccessGenerate) isHs() bool {
	return strings.HasPrefix(a.SignedMethod.Alg(), "HS")
}