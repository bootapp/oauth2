package oauth2

import (
	"time"
)

type (
	// ClientInfo the client information model interface
	ClientInfo interface {
		GetID() string
		GetSecret() string
		GetDomain() string
		GetUserID() int64
	}

	// TokenInfo the token information model interface
	TokenInfo interface {
		New() TokenInfo

		GetClientID() string
		SetClientID(string)
		GetUserID() int64
		SetUserID(int64)
		GetOrgID() int64
		SetOrgID(int64)
		GetRedirectURI() string
		SetRedirectURI(string)
		GetScope() string
		SetScope(string)
		GetAuthorities () map[uint64]uint64
		SetAuthorities (map[uint64]uint64)

		GetExpiresAt () time.Time
		SetExpiresAt (time.Time)

		GetCode() string
		SetCode(string)
		GetCodeCreateAt() time.Time
		SetCodeCreateAt(time.Time)
		GetCodeExpiresIn() time.Duration
		SetCodeExpiresIn(time.Duration)

		GetAccess() string
		SetAccess(string)
		GetAccessCreateAt() time.Time
		SetAccessCreateAt(time.Time)
		GetAccessExpiresIn() time.Duration
		SetAccessExpiresIn(time.Duration)

		GetRefresh() string
		SetRefresh(string)
		GetRefreshCreateAt() time.Time
		SetRefreshCreateAt(time.Time)
		GetRefreshExpiresIn() time.Duration
		SetRefreshExpiresIn(time.Duration)
	}
)
