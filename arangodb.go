package arangodb

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/arangodb/go-driver"
	"github.com/arangodb/go-driver/http"
	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
)

var _ dbplugin.Database = (*ArangoDB)(nil)

type ArangoDB struct {
	mux    sync.RWMutex
	client driver.Client
}

func New() (interface{}, error) {
	db := &ArangoDB{}
	return dbplugin.NewDatabaseErrorSanitizerMiddleware(db, db.SecretValues), nil
}

func (db *ArangoDB) SecretValues() map[string]string {
	return nil
}

func (db *ArangoDB) Type() (string, error) {
	return "arangodb", nil
}

func (db *ArangoDB) Initialize(ctx context.Context, req dbplugin.InitializeRequest) (dbplugin.InitializeResponse, error) {
	newClient, err := db.createClient(req.Config)
	if err != nil {
		return dbplugin.InitializeResponse{}, err
	}

	if req.VerifyConnection {
		if _, err := newClient.Users(ctx); err != nil {
			return dbplugin.InitializeResponse{}, fmt.Errorf("failed to verify connection: %w", err)
		}
	}

	db.mux.Lock()
	defer db.mux.Unlock()
	db.client = newClient

	return dbplugin.InitializeResponse{
		Config: req.Config,
	}, nil
}

func (db *ArangoDB) NewUser(ctx context.Context, req dbplugin.NewUserRequest) (dbplugin.NewUserResponse, error) {
	username, err := credsutil.GenerateUsername(
		credsutil.DisplayName(req.UsernameConfig.DisplayName, 15),
		credsutil.RoleName(req.UsernameConfig.RoleName, 15),
		credsutil.MaxLength(100),
		credsutil.Separator("-"),
	)
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("unable to generate username for %q: %w", req.UsernameConfig, err)
	}

	permissions, err := permissionsFromStatements(req.Statements)
	if err != nil {
		return dbplugin.NewUserResponse{}, err
	}

	db.mux.RLock()
	defer db.mux.RUnlock()
	if db.client == nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("connection not initialized")
	}

	user, err := db.client.CreateUser(ctx, username, &driver.UserOptions{
		Password: req.Password,
	})
	if err != nil {
		return dbplugin.NewUserResponse{}, fmt.Errorf("failed to create new user: %w", err)
	}

	if err := db.grantPermissions(ctx, user, permissions); err != nil {
		// TODO: not really sure what to do in these cases, for now let's just try cleaning up
		user.Remove(ctx)
		return dbplugin.NewUserResponse{}, err
	}

	return dbplugin.NewUserResponse{
		Username: username,
	}, nil
}

func (db *ArangoDB) UpdateUser(ctx context.Context, req dbplugin.UpdateUserRequest) (dbplugin.UpdateUserResponse, error) {
	db.mux.Lock()
	defer db.mux.Unlock()
	if db.client == nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("connection not initialized")
	}

	user, err := db.client.User(ctx, req.Username)
	if err != nil {
		return dbplugin.UpdateUserResponse{}, fmt.Errorf("failed to read user data: %w", err)
	}

	if req.Password != nil {
		if err := user.Update(ctx, driver.UserOptions{
			Password: req.Password.NewPassword,
		}); err != nil {
			return dbplugin.UpdateUserResponse{}, fmt.Errorf("failed to update password: %w", err)
		}
	}

	return dbplugin.UpdateUserResponse{}, nil
}

func (db *ArangoDB) DeleteUser(ctx context.Context, req dbplugin.DeleteUserRequest) (dbplugin.DeleteUserResponse, error) {
	db.mux.RLock()
	defer db.mux.RUnlock()
	if db.client == nil {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("connection not initialized")
	}

	user, err := db.client.User(ctx, req.Username)
	if err != nil {
		if driver.IsNotFound(err) {
			return dbplugin.DeleteUserResponse{}, nil
		}

		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to read user data: %w", err)
	}

	err = user.Remove(ctx)
	if err != nil && !driver.IsNotFound(err) {
		return dbplugin.DeleteUserResponse{}, fmt.Errorf("failed to remove user: %w", err)
	}

	return dbplugin.DeleteUserResponse{}, nil
}

func (db *ArangoDB) Close() error {
	// nop
	return nil
}

func (db *ArangoDB) createClient(raw map[string]interface{}) (driver.Client, error) {
	config, err := configFromRaw(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse config data: %w", err)
	}

	var tlsConfig *tls.Config
	if config.Insecure {
		tlsConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	conn, err := http.NewConnection(http.ConnectionConfig{
		Endpoints: strings.Split(config.Endpoints, ","),
		TLSConfig: tlsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection: %w", err)
	}

	client, err := driver.NewClient(driver.ClientConfig{
		Connection:     &CookieConnection{Connection: conn},
		Authentication: driver.BasicAuthentication(config.Username, config.Password),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create new client: %w", err)
	}

	return client, nil
}

func (db *ArangoDB) grantPermissions(ctx context.Context, user driver.User, permissions []Permission) error {
	for _, permission := range permissions {
		var database driver.Database
		if len(permission.Database) > 0 && permission.Database != "*" {
			pdb, err := db.client.Database(ctx, permission.Database)
			if err != nil {
				return fmt.Errorf("failed to read database data: %w", err)
			}
			database = pdb
		}

		if permission.Collection == "" || permission.Collection == "*" {
			if err := user.SetDatabaseAccess(ctx, database, driver.Grant(permission.Grant)); err != nil {
				return fmt.Errorf("failed to set database access for the user: %w", err)
			}
		} else {
			col, err := database.Collection(ctx, permission.Collection)
			if err != nil {
				return fmt.Errorf("failed to read collection data: %w", err)
			}

			if err := user.SetCollectionAccess(ctx, col, driver.Grant(permission.Grant)); err != nil {
				return fmt.Errorf("failed to set collection access for the user: %w", err)
			}
		}
	}

	return nil
}

type CookieConnection struct {
	driver.Connection
	cookie string
	mutex  sync.RWMutex
}

func (cc *CookieConnection) Do(ctx context.Context, req driver.Request) (driver.Response, error) {
	cc.mutex.RLock()
	if len(cc.cookie) > 0 {
		req.SetHeader("Cookie", cc.cookie)
	}
	cc.mutex.RUnlock()
	res, err := cc.Connection.Do(ctx, req)
	if err != nil {
		return nil, err
	}
	cookie := res.Header("Set-Cookie")
	if len(cookie) > 0 {
		cc.mutex.Lock()
		cc.cookie = cookie
		cc.mutex.Unlock()
	}
	return res, nil
}

func (cc *CookieConnection) SetAuthentication(auth driver.Authentication) (driver.Connection, error) {
	conn, err := cc.Connection.SetAuthentication(auth)
	if err != nil {
		return nil, err
	}
	return &CookieConnection{Connection: conn}, nil
}
