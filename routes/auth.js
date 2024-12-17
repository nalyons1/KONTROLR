// --------------- Routes for QBO Authentication and SQL Backups -----------------------//

// routes/auth.js
const express = require('express');
const router = express.Router();
module.exports = router;
const axios = require('axios');
const qs = require('querystring');
const crypto = require('crypto'); // To generate random state strings
const pg = require('pg');
const { Pool } = require('pg');
const { access } = require('fs');

// import .env variables
require('dotenv').config();

// PostgreSQL Database Connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: 5432,
    ssl: { rejectUnauthorized: false },
});

// Configuration for your QuickBooks app
const clientId = process.env.QBO_CLIENT_ID;
const clientSecret = process.env.QBO_CLIENT_SECRET;
const redirectUri = process.env.QBO_REDIRECT_URI;
const companyId = process.env.QBO_COMPANY_ID;
const refreshUri = process.env.QBO_REFRESHTOKEN_URI;
const baseUrl = process.env.QBO_BASE_URL;

let accessToken = ''; // Access token will be dynamically fetched
let refreshToken = ''; // Token used for refreshing access token
let oauthState = ''; // Temporary storage for the state parameter

// Generate a random state string
const generateState = () => crypto.randomBytes(16).toString('hex');

// ------------------------ ROUTES --------------------------------- //

// Route to start OAuth process
router.get('/auth', (req, res) => {
    oauthState = generateState(); // Generate a unique state for this session

    const authUrl = `https://appcenter.intuit.com/connect/oauth2?` +
        `client_id=${clientId}` +
        `&response_type=code` +
        `&scope=com.intuit.quickbooks.accounting` +
        `&redirect_uri=${encodeURIComponent(redirectUri)}` +
        `&state=${oauthState}`;

    console.log('Redirecting to authorization URL:', authUrl);
    res.redirect(authUrl);
});

// ------ Encryption Setup ------ //

const algorithm = 'aes-256-cbc';
const encryptionKey = process.env.ENCRYPTION_KEY; // Ensure this is 32 bytes
const encryptToken = (token) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(algorithm, encryptionKey, iv);
    let encrypted = cipher.update(token, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return `${iv.toString('hex')}:${encrypted}`;
};

// ------ Decryption Setup ------ //
const decryptToken = (encryptedToken) => {
    const [ivHex, encryptedData] = encryptedToken.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(algorithm, encryptionKey, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
};

// ------ Callback route to handle QBO response ------ //
router.get('/callback', async (req, res) => {
    const { code, state } = req.query;

    if (!code) {
        return res.redirect('/account?message=Authorization failed: No code provided.&status=error');
    }

    if (state !== oauthState) {
        return res.redirect('/account?message=Authorization failed: Invalid state parameter.&status=error');
    }

    try {
        // Exchange authorization code for tokens
        const tokenResponse = await axios.post(
            'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
            qs.stringify({
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: redirectUri,
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
                },
            }
        );

        const { access_token, refresh_token, expires_in } = tokenResponse.data;

        // Calculate the token expiry timestamp
        const token_expiry = new Date();
        token_expiry.setSeconds(token_expiry.getSeconds() + expires_in);

        const last_refresh = new Date();
        const userId = req.session.userId;

        // Encrypt the tokens
        const encryptedAccessToken = encryptToken(access_token);
        const encryptedRefreshToken = encryptToken(refresh_token);

        // console.log('Encrypted Access Token:', encryptedAccessToken);
        // console.log('Encrypted Refresh Token:', encryptedRefreshToken);

        // Store encrypted tokens and timestamps in the database
        const client = await pool.connect();
        await client.query(
            `
            INSERT INTO user_tokens (user_id, access_token, refresh_token, token_expiry, last_refresh)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (user_id)
            DO UPDATE SET 
                access_token = EXCLUDED.access_token,
                refresh_token = EXCLUDED.refresh_token,
                token_expiry = EXCLUDED.token_expiry,
                last_refresh = EXCLUDED.last_refresh
            `,
            [userId, encryptedAccessToken, encryptedRefreshToken, token_expiry, last_refresh]
        );
        client.release();

        // Redirect to account with success message
        res.redirect('/account?message=QuickBooks Authorization successful!&status=success');
    } catch (error) {
        console.error('Error during token exchange:', error.message);
        res.redirect('/account?message=Authorization failed: Unable to exchange tokens.&status=error');
    }
});

// ------ Refresh Token Route ------ //
router.get('/refresh-token', async (req, res) => {
    const userId = req.session.userId;

    if (!userId) {
        return res.status(401).redirect('/account?message=Unauthorized. Please log in.&status=error');
    }

    try {
        // Retrieve the encrypted refresh_token from the database
        const client = await pool.connect();
        let encryptedRefreshToken;
        try {
            const result = await client.query(
                `SELECT refresh_token FROM user_tokens WHERE user_id = $1`,
                [userId]
            );

            if (result.rowCount === 0) {
                return res.status(404).redirect('/account?message=Refresh token not found. Please reconnect QuickBooks.&status=error');
            }

            encryptedRefreshToken = result.rows[0].refresh_token;
        } finally {
            client.release();
        }

        // Decrypt the refresh token
        const decryptedRefreshToken = decryptToken(encryptedRefreshToken);

        // Make API call to refresh tokens
        const refreshResponse = await axios.post(
            'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer',
            qs.stringify({
                grant_type: 'refresh_token',
                refresh_token: decryptedRefreshToken,
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    Authorization: `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`,
                },
            }
        );

        const newAccessToken = refreshResponse.data.access_token;
        const newRefreshToken = refreshResponse.data.refresh_token;

        // Encrypt the new tokens
        const encryptedAccessToken = encryptToken(newAccessToken);
        const encryptedNewRefreshToken = encryptToken(newRefreshToken);

        // Update the database with the new tokens
        const clientUpdate = await pool.connect();
        try {
            await clientUpdate.query(
                `
                UPDATE user_tokens 
                SET access_token = $1, refresh_token = $2, token_expiry = $3, last_refresh = NOW()
                WHERE user_id = $4
                `,
                [
                    encryptedAccessToken,
                    encryptedNewRefreshToken,
                    new Date(Date.now() + refreshResponse.data.expires_in * 1000),
                    userId,
                ]
            );
        } finally {
            clientUpdate.release();
        }

        res.redirect('/account?message=Tokens refreshed successfully!&status=success');
    } catch (error) {
        console.error('Error during token refresh:', error.message);

        // Delete token record on failure
        const clientDelete = await pool.connect();
        try {
            await clientDelete.query(
                `DELETE FROM user_tokens WHERE user_id = $1`,
                [userId]
            );
            console.log(`Deleted token record for user ID: ${userId} due to refresh failure.`);
        } finally {
            clientDelete.release();
        }

        res.redirect(`/account?message=Token refresh failed. Please reconnect QuickBooks.&status=error`);
    }
});

// Pull Access Token from SQL and make available to fetchQBOData functions below
const getAccessToken = async (userId) => {
    try {
        console.log(`Fetching access token for userId: ${userId}`);

        // Fetch the encrypted access token from the database
        const tokenQuery = 'SELECT access_token FROM user_tokens WHERE user_id = $1';
        const { rows } = await pool.query(tokenQuery, [userId]);

        if (rows.length === 0) {
            throw new Error(`Access token not found for userId: ${userId}`);
        }

        // Decrypt the access token
        const encryptedAccessToken = rows[0].access_token;
        const encryptionKey = process.env.ENCRYPTION_KEY;
        const accessToken = decryptToken(encryptedAccessToken, encryptionKey);

        console.log(`Decrypted access token for userId: ${userId}`);
        return accessToken;
    } catch (error) {
        console.error(`Error retrieving access token for userId: ${userId}`, error.message);
        throw error; // Re-throw the error to handle it in the calling function
    }
};


// ------ Sync Data Route ------ //

router.get('/syncdata', async (req, res) => {
    const userId = req.session.userId;
    console.log(`Starting data sync for userId: ${userId}`);

    if (!userId) {
        return res.status(401).redirect('/account?message=Unauthorized. Please log in.&status=error');
    }

    try {
        // Step 1: Refresh token
        const refreshResponse = await axios.get(refreshUri, {
            headers: { Cookie: req.headers.cookie },
        });

        if (refreshResponse.status !== 200) {
            return res.redirect('/account?message=Token refresh failed. Please reconnect QuickBooks.&status=error');
        }

        // Step 2: Sync data (first-time or incremental handled in fetchGeneralLedgerData)
        await syncQBOData(userId);

        // Step 3: Respond with success
        res.redirect('/account?message=Data synced successfully!&status=success');
    } catch (error) {
        console.error('Error syncing data:', error.message);

        // Step 4: Respond with error
        res.redirect('/account?message=Error syncing data. Please try again later.&status=error');
    }
});


const syncQBOData = async (userId) => {
    
    console.log('Syncing first-time data...');
    const accountsData = await fetchQBOAccountsData(userId); 
    await pushAccountsDataToSQL(accountsData, userId);
    const glData = await fetchGeneralLedgerData(userId); 
    console.log('GL data acquired.');
    await pushGlDataToSQL(glData, userId); 
};

// ------------ Functions to Fetch QBO data ------------ //

const fetchQBOAccountsData = async (userId) => {
    try {
        // Step 1: Retrieve access token
        const accessToken = await getAccessToken(userId);

        // Step 2: Query the QBO API
        console.log(`Querying QBO API for userId: ${userId}`);
        const query = "SELECT * FROM Account";
        const response = await axios.get(
            `${baseUrl}/v3/company/${companyId}/query`,
            {
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    Accept: 'application/json',
                },
                params: { query },
            }
        );

        if (response.status === 200) {
            const accounts = response.data.QueryResponse.Account || [];

            // Create the DataFrame-like structure
            const accountsDataFrame = accounts.map(account => ({
                id: account.Id,
                name: account.Name,
                type: account.AccountType,
                subType: account.AccountSubType || 'N/A',
            }));

            globalAccountsDataFrame = accountsDataFrame; // Save for later use
            console.log(`Accounts fetched and processed successfully for userId: ${userId}`);
            return accountsDataFrame;
        } else {
            throw new Error(`QBO API request failed with status: ${response.status}`);
        }
    } catch (error) {
        console.error(`Error in fetchQBOAccountsData for userId: ${userId}`, error.message);
        throw error; // Optionally re-throw the error to handle it in the calling function
    }
};

const fetchGeneralLedgerData = async (userId) => {
    let client; // To manage the database connection
    try {
        const accessToken = await getAccessToken(userId);
        if (!accessToken) {
            throw new Error('Connection failed: No access token.');
        }

        // Determine the start_date
        client = await pool.connect();
        const queryText = 'SELECT MAX(create_date) AS last_create_date FROM general_ledger WHERE user_id = $1';
        const result = await client.query(queryText, [userId]);
        let startDate = '2022-01-01'; // Default start date
        if (result.rows.length > 0 && result.rows[0].last_create_date) {
            startDate = new Date(result.rows[0].last_create_date).toISOString().split('T')[0];
        }
        console.log(`Using start_date: ${startDate}`);

        // Fetch data from QBO API
        const url = `${baseUrl}/v3/company/${companyId}/reports/GeneralLedger`;
        const params = {
            start_date: startDate,
            end_date: new Date().toISOString().split('T')[0],
            accounting_method: 'Accrual',
            //account_type: 'Income',
            columns: 'tx_date,txn_type,last_mod_date,create_date,name,cust_name,vend_name,memo,account_name,split_acc,subt_nat_amount',
            minorversion: 73,
        };

        const response = await axios.get(url, {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                Accept: 'application/json',
            },
            params,
        });

        // Flatten response data
        const flattenRows = (rows, headers = []) => {
            const result = [];
            rows.forEach((row) => {
                if (row.Rows?.Row) {
                    result.push(...flattenRows(row.Rows.Row, headers));
                } else if (row.ColData) {
                    const record = {};
                    row.ColData.forEach((col, index) => {
                        const header = headers[index] || `unknown_${index}`;
                        record[header] = col.value || ''; // Assign value or empty string if undefined
                    });

                    if (record.tx_date !== 'Beginning Balance') {
                        result.push(record);
                    }
                }
            });
            return result;
        };

        const headers = params.columns.split(',');
        const flattenedData = flattenRows(response.data.Rows?.Row || [], headers);

        // Deduplicate rows
        const uniqueData = Array.from(
            new Map(flattenedData.map((row) => [JSON.stringify(row), row])).values()
        );

        return uniqueData;
    } catch (error) {
        console.error('Error fetching General Ledger data:', error.response?.data || error.message);
        throw error;
    } finally {
        if (client) client.release();
    }
};




// ------------  Functions to push QBO data to SQL ------------//

const pushAccountsDataToSQL = async (accountsData, userId) => {
    try {
        console.log('Pushing accounts data to SQL...');

        if (!accountsData || accountsData.length === 0) {
            console.log('No data to push.');
            return;
        }

        // Open a connection
        const client = await pool.connect();

        // Begin a transaction
        await client.query('BEGIN');

        // Check if there is existing data for the user and delete it
        const deleteQuery = 'DELETE FROM chart_of_accounts WHERE user_id = $1';
        await client.query(deleteQuery, [userId]);
        console.log(`Existing data for user_id ${userId} cleared.`);

        // Insert each account into the database
        for (const account of accountsData) {
            const queryText = `
                INSERT INTO chart_of_accounts (account_id, name, type, subtype, user_id)
                VALUES ($1, $2, $3, $4, $5)
            `;
            const values = [account.id, account.name, account.type, account.subType, userId];

            await client.query(queryText, values);
        }

        // Commit the transaction
        await client.query('COMMIT');
        console.log('Data pushed successfully.');

        // Release the connection
        client.release();
    } catch (error) {
        console.error('Error pushing data to SQL:', error.message);

        // Rollback the transaction in case of error
        if (client) {
            await client.query('ROLLBACK');
        }
    }
};


const pushGlDataToSQL = async (glData, userId) => {
    let client; // Declare client here to make sure it's defined in both try and catch blocks
    try {
        console.log('Pushing GL data to SQL...');

        if (!glData || glData.length === 0) {
            console.log('No data to push.');
            return;
        }

        // Open a connection
        client = await pool.connect();

        // Begin a transaction
        await client.query('BEGIN');

        // Helper function to sanitize data
        function sanitizeRow(row) {
            return {
                tx_date: row.tx_date || null,
                txn_type: row.txn_type || null,
                create_date: row.create_date || null,
                last_mod_date: row.last_mod_date || null,
                cust_name: row.cust_name || null,
                name: row.name || null,
                vend_name: row.vend_name || null,
                memo: row.memo || null,
                split_acc: row.split_acc || null,
                account_name: row.account_name || null,
                subt_nat_amount: row.subt_nat_amount && !isNaN(row.subt_nat_amount) 
                    ? parseFloat(row.subt_nat_amount) 
                    : null,  // Convert to float or null if not valid
            };
        }

        // Insert each sanitized account into the database
        for (const general_ledger of glData) {
            const sanitizedEntry = sanitizeRow(general_ledger);

            const queryText = `
                INSERT INTO general_ledger (tx_date, txn_type, create_date, last_mod_date, cust_name, name, vend_name, memo, account_name, split_acc, subt_nat_amount, user_id)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            `;
            const values = [
                sanitizedEntry.tx_date,
                sanitizedEntry.txn_type,
                sanitizedEntry.create_date,
                sanitizedEntry.last_mod_date,
                sanitizedEntry.cust_name,
                sanitizedEntry.name,
                sanitizedEntry.vend_name,
                sanitizedEntry.memo,
                sanitizedEntry.account_name,
                sanitizedEntry.split_acc,
                sanitizedEntry.subt_nat_amount,
                userId
            ];

            await client.query(queryText, values);
        }

        // Commit the transaction
        await client.query('COMMIT');
        console.log('Data pushed successfully.');

        // Release the connection
        client.release();
    } catch (error) {
        console.error('Error pushing data to SQL:', error.message);

        // Rollback the transaction in case of error
        if (client) {
            await client.query('ROLLBACK');
            client.release();
        }
    }
};
