// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mssql

import (
	"database/sql"
	"io"
	"log"
	"os"
	"strings"

	// Register driver.
	_ "github.com/denisenkom/go-mssqldb"

	"github.com/pkg/errors"
)

// debugLogger is used for MSSQL connection debugging
var debugLogger *log.Logger

func init() {
	logFile, err := os.OpenFile("/usr/local/easyops/easy_metric_sampler/log/beats.log",
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		// Fall back to discard if log file cannot be opened
		debugLogger = log.New(io.Discard, "", 0)
	} else {
		debugLogger = log.New(logFile, "[beats/mssql] ", log.LstdFlags|log.Lmicroseconds)
	}
}

// NewConnection returns a connection already established with MSSQL
func NewConnection(uri string) (*sql.DB, error) {
	// Mask password in log output
	maskedURI := maskPassword(uri)
	debugLogger.Printf("NewConnection: opening connection to %s", maskedURI)

	db, err := sql.Open("sqlserver", uri)
	if err != nil {
		debugLogger.Printf("NewConnection: sql.Open failed: %v", err)
		return nil, errors.Wrap(err, "could not create db instance")
	}
	debugLogger.Printf("NewConnection: sql.Open succeeded, now pinging...")

	// Check the connection before executing all queries to reduce the number
	// of connection errors that we might encounter.
	if err = db.Ping(); err != nil {
		debugLogger.Printf("NewConnection: db.Ping FAILED: %v", err)
		err = errors.Wrap(err, "error doing ping to db")
	} else {
		debugLogger.Printf("NewConnection: db.Ping succeeded, connection established")
	}

	return db, err
}

// BuildURI constructs a connection URI with optional parameters from module config.
// It appends tlsmin parameter if tlsMinVersion is configured.
func BuildURI(baseURI string, config map[string]interface{}) string {
	uri := baseURI

	debugLogger.Printf("BuildURI: baseURI=%s", maskPassword(baseURI))
	debugLogger.Printf("BuildURI: config=%+v", config)

	// Append tlsmin parameter if configured
	if tlsMinVal, ok := config["tlsMinVersion"].(string); ok && tlsMinVal != "" {
		debugLogger.Printf("BuildURI: tlsMinVersion found in config: %s", tlsMinVal)
		if strings.Contains(uri, "?") {
			uri = uri + "&tlsmin=" + tlsMinVal
		} else {
			uri = uri + "?tlsmin=" + tlsMinVal
		}
		debugLogger.Printf("BuildURI: final URI=%s", maskPassword(uri))
	} else {
		debugLogger.Printf("BuildURI: tlsMinVersion not found in config or empty")
	}

	return uri
}

// maskPassword masks the password in a connection URI for safe logging
func maskPassword(uri string) string {
	// Handle sqlserver://user:password@host format
	if idx := strings.Index(uri, "://"); idx != -1 {
		schemeEnd := idx + 3
		rest := uri[schemeEnd:]
		if atIdx := strings.Index(rest, "@"); atIdx != -1 {
			userPart := rest[:atIdx]
			hostPart := rest[atIdx:]
			if colonIdx := strings.Index(userPart, ":"); colonIdx != -1 {
				user := userPart[:colonIdx]
				return uri[:schemeEnd] + user + ":***" + hostPart
			}
		}
	}
	return uri
}
