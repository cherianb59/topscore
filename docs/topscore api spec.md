# TopScore API Specification v0.3

https://docs.google.com/document/d/148SFmTpsdon5xoGpAeNCokrpaPKKOSDtrLNBHOIq5c4/edit?tab=t.0

[Overview](#overview)

[SSL](#ssl)

[User Agent](#user-agent)

[Basic Authentication](#basic-authentication)

[auth\_token](#auth_token)

[api\_csrf](#api_csrf)

[authentication test](#authentication-test)

[OAuth2 Authentication](#oauth2-authentication)

[oauth\_token](#oauth_token)

[Generate a Token](#generate-a-token)

[User Login](#user-login)

[Endpoint Requests](#endpoint-requests)

[Pagination](#pagination)

[Additional Fields](#additional-fields)

[Self-Documentation](#self-documentation)

[API Response](#api-response)

[status](#status)

[count](#count)

[result](#result)

[errors](#errors)

# Overview {#overview}

The API accepts GET or POST requests and returns JSON. GET requests are used to retrieve information. GET requests do not require authentication, though some information will not be available without proper credentials (e.g. hidden events, non-public user information, etc). POST requests are used to make changes (e.g. create new events, edit schedules, send messages, etc). They always require authentication.

Note: we are now offering two levels of authentication:  basic and OAuth2

# SSL {#ssl}

All API requests must be made over SSL. **Since most organizations do not have an SSL certificate for their custom domain, API requests have to be done using our \*.usetopscore.com domain, which is protected by our certificate.** If you do not know what domain to use, go to yoursite.com/u/auth-key and use the API domain listed there (or yoursite.com/u/oauth-key for OAuth2).

# User Agent {#user-agent}

To pass our firewall and our bot filters, we recommend specifying the user-agent header as follows

TopScore API v1.0.0

# Basic Authentication {#basic-authentication}

## auth\_token {#auth_token}

Every user has a Client ID. You can see your Client ID by going to yoursite.com/u/auth-key. This ID identifies you as the user of the current user of an API request. It must be passed to the API using

?auth\_token=CLIENT\_ID

## api\_csrf {#api_csrf}

All POST requests must be signed with the user’s Client Secret. You can see your Client Secret by going to [yoursite.com/u/auth-key](http://yoursite.com/u/auth-key) (note: this URL is different from the OAuth2 Authentication URL). Treat your Client Secret as a password \- never share it with anyone, never publish it, and never include it in client-side Javascript.

To create a signature for an API request, concatenate your client id, a random nonce (must be at least 10 characters long), and the current unix timestamp (seconds since the epoch). Then compute the [base64url-encoded](https://tools.ietf.org/html/rfc4648#section-5) HMAC-SHA256 hash of this concatenated string, using your client secret as the key. Finally, concatenate the nonce, timestamp and HMAC hash (separated by ‘|’ characters) and base64url-encode it to create the signature.

nonce \= \<random string, at least 10 characters long\>  
timestamp \= \<current unix timestamp\>  
hmac \= base64\_url\_encode(hmac\_sha256(CLIENT\_ID \+ nonce \+ timestamp, CLIENT\_SECRET))  
SIGNATURE \= base64\_url\_encode(nonce \+ ‘|’ \+ timestamp \+ ‘|’ \+ hmac)

Pass this signature to the API using

?auth\_token=CLIENT\_ID\&api\_csrf=SIGNATURE

A signature is valid for 1 hour, after which time it expires. 

## authentication test {#authentication-test}

You can test that your request is authenticated correctly by using the /api/me endpoint. A successful request to this endpoint will return a 200 response which contains your person\_id and an api\_csrf\_valid field which indicates if you’re using a valid api\_csrf signature. A 401 response indicates that the auth\_token is missing or invalid. You may also get a 419 response, which indicates that the auth\_token is valid but the api\_csrf signature is invalid or has expired.

Note: If you use a GET request, only the auth\_token parameter will be validated and the api\_csrf parameter will be ignored. If you use a POST, both the auth\_token and the api\_csrf parameters will be validated.

# OAuth2 Authentication {#oauth2-authentication}

We purposefully limit our basic authentication in terms of what data is exposed.  The higher security of OAuth2 enables us to safely expose more data via the API.

## oauth\_token {#oauth_token}

Login to get your OAuth credentials (client\_id and client\_secret):  [yoursite.com/u/**o**auth-key](http://yoursite.com/u/oauth-key) (note: this URL is different from the Basic Authentication URL)

## Generate a Token {#generate-a-token}

You can POST your oauth\_token to get an access token.  An example request would be  
curl  "yoursite.usetopscore.com/api/oauth/server" \-d "grant\_type=client\_credentials\&client\_id=\[YOUR\_CLIENT\_ID\]\&client\_secret=\[YOUR\_CLIENT\_SECRET\]"

The JSON response will include an access token connected to the user whose OAuth credentials are being used.

## User Login {#user-login}

To login as a user, POST their credentials in a request along with your OAuth key credentials  
curl  "yoursite.usetopscore.com/api/oauth/server" \-d "grant\_type=password\&client\_id=\[YOUR\_CLIENT\_ID\]\&client\_secret=\[YOUR\_CLIENT\_SECRET\]\&username=\[USR\_EMAIL\]\&password=\[USR\_PWD\]"

The JSON response will include an access token connected to the newly logged in user’s account.

## Endpoint Requests {#endpoint-requests}

Now that you have a token you can securely access TopScore endpoints. Note that for these  requests the access token must be sent via the Authorization header 

For example, making a GET request to the /api/persons/me endpoint would look like this:  
curl yoursite.usetopscore.com/api/persons/me \-H "Authorization: Bearer \[YOUR\_ACCESS\_TOKEN\]"

# Pagination {#pagination}

All GET responses are paginated. Every GET response supports the page and per\_page parameters to control pagination. By default, page \= 1 and per\_page \= 10\. per\_page cannot be more than 100\.

# Additional Fields {#additional-fields}

Most responses only return data for the primary model of the request. To embed data for related models, use the fields parameter. fields can be a simple array or an associative array of relations. For example, when listing registrations, fields could look like: \[“Person”, “Team”, “Event” \=\> “Location”, “Purchase” \=\> \[“Transaction”, “Product”\]\]

# Self-Documentation {#self-documentation}

Every API endpoint is self-documenting with up-to-date information about what fields it accepts and the requirements for each field. To see the full documentation, use the /api/help endpoint. You can also use /api/help?endpoint=ENDPOINT to limit the documentation to a specific endpoint.

# API Response {#api-response}

An API response is always a JSON object. It is guaranteed to have the following fields:

## status {#status}

The HTTP status code of the response. This is always identical to the actual HTTP response code used, and is duplicated in JSON for your convenience. Status codes have standard RESTful-ish meanings: 2XX \= success, 4XX \= error, 5XX \= we screwed up.

## count {#count}

Count is the total number of results found. This may be different from result.length because of pagination.

## result {#result}

An array of the results. If there is an error, the results array will always be empty.

## errors {#errors}

An array of errors. Each error has the following fields:

message \- a human-readable message describing the error

field \- the API field that the error relates to (will be null if the error is not related to a field)

data \- an object with extra data related to the error (will be null if there is no extra data)