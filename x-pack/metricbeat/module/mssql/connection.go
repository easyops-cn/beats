// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package mssql

import (
	"database/sql"
	"strings"

	// Register driver.
	_ "github.com/denisenkom/go-mssqldb"

	"github.com/pkg/errors"
)

// NewConnection returns a connection already established with MSSQL
func NewConnection(uri string) (*sql.DB, error) {
	db, err := sql.Open("sqlserver", uri)
	if err != nil {
		return nil, errors.Wrap(err, "could not create db instance")
	}

	// Check the connection before executing all queries to reduce the number
	// of connection errors that we might encounter.
	if err = db.Ping(); err != nil {
		err = errors.Wrap(err, "error doing ping to db")
	}

	return db, err
}

// BuildURI constructs a connection URI with optional parameters from module config.
// It appends tlsmin parameter if tlsMinVersion is configured.
func BuildURI(baseURI string, config map[string]interface{}) string {
	uri := baseURI

	// Append tlsmin parameter if configured
	if tlsMinVal, ok := config["tlsMinVersion"].(string); ok && tlsMinVal != "" {
		if strings.Contains(uri, "?") {
			uri = uri + "&tlsmin=" + tlsMinVal
		} else {
			uri = uri + "?tlsmin=" + tlsMinVal
		}
	}

	return uri
}
