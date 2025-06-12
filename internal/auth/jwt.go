package auth

import (
	"fmt"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Claims struct {
	NodeID    string `json:"node_id"`
	NodeName  string `json:"node_name"`
	IsAdmin   bool   `json:"is_admin,omitempty"`
	AdminUser string `json:"admin_user,omitempty"`
	jwt.RegisteredClaims
}

func (a *AuthManager) GenerateAccessToken(nodeID string) (string, error) {
	node, err := a.db.GetNode(nodeID)
	if err != nil {
		a.logger.WithError(err).Error("Failed to get node for token generation")
		return "", pkg.DatabaseError(err)
	}

	if node == nil {
		return "", pkg.NotFoundError("Node not found")
	}

	claims := &Claims{
		NodeID:   node.ID,
		NodeName: node.Name,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arrowhead-lite",
			Subject:   node.ID,
			ID:        uuid.New().String(),
		},
	}

	var token *jwt.Token
	var tokenString string

	if a.privateKey != nil {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = token.SignedString(a.privateKey)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString(a.jwtSecret)
	}

	if err != nil {
		a.logger.WithError(err).Error("Failed to sign token")
		return "", pkg.InternalServerError("Failed to generate access token")
	}

	return tokenString, nil
}

func (a *AuthManager) GenerateAdminToken(adminUser string) (string, error) {
	claims := &Claims{
		IsAdmin:   true,
		AdminUser: adminUser,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    "arrowhead-lite",
			Subject:   "admin:" + adminUser,
			ID:        uuid.New().String(),
		},
	}

	var token *jwt.Token
	var tokenString string
	var err error

	if a.privateKey != nil {
		token = jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tokenString, err = token.SignedString(a.privateKey)
	} else {
		token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err = token.SignedString(a.jwtSecret)
	}

	if err != nil {
		a.logger.WithError(err).Error("Failed to sign admin token")
		return "", pkg.InternalServerError("Failed to generate admin token")
	}

	return tokenString, nil
}

func (a *AuthManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		switch token.Method {
		case jwt.SigningMethodRS256:
			if a.publicKey == nil {
				return nil, fmt.Errorf("no public key configured for RS256")
			}
			return a.publicKey, nil
		case jwt.SigningMethodHS256:
			return a.jwtSecret, nil
		default:
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
	})

	if err != nil {
		a.logger.WithError(err).Error("Failed to parse token")
		return nil, pkg.UnauthorizedError("Invalid token")
	}

	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, pkg.UnauthorizedError("Invalid token claims")
}
