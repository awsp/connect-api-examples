<?php

# Demonstrates a server listening for webhook notifications from the Square Connect API
#
# This sample requires the Unirest PHP library. See README.md in this directory for
# installation instructions.
#
# See Webhooks Overview for more information:
# https://docs.connect.squareup.com/api/connect/v1/#webhooks-overview

require 'vendor/autoload.php';

# Your application's access token
$accessToken = 'REPLACE_ME';

# Your application's webhook signature key, available from your application dashboard
$webhookSignatureKey = 'REPLACE_ME';

# The URL that this server is listening on (e.g., 'http://example.com/events')
# Note that to receive notifications from Square, this cannot be a localhost URL
$webhookUrl = 'REPLACE_ME';

# The base URL for every Connect API request
$connectHost = 'https://connect.squareup.com';

# Headers to provide to Connect API endpoints
$requestHeaders = array (
  'Authorization' => 'Bearer ' . $accessToken,
  'Accept' => 'application/json',
  'Content-Type' => 'application/json'
);

# Retrieves payments by the IDs provided in webhook notifications.
#
# Note that you need to set your application's webhook URL from your application dashboard
# to receive these notifications. In this sample, if your host's base URL is
# http://example.com, you'd set your webhook URL to http://example.com/webhooks.php.
function webhookCallback() {
  global $connectHost, $requestHeaders;

  if ($_SERVER['REQUEST_METHOD'] == 'POST') {

    # Get the JSON body and HMAC-SHA1 signature of the incoming POST request
    $callbackBody = file_get_contents('php://input');
    $callbackSignature = getallheaders()['X-Square-Signature'];

    # Validate the signature
    if (!isValidCallback($callbackBody, $callbackSignature)){

      # Fail if the signature is invalid
      error_log("Webhook event with invalid signature detected!");
      return;
    }

    # Load the JSON body into an associative array
    $callbackBodyJson = json_decode($callbackBody);

    # If the notification indicates a PAYMENT_UPDATED event...
    # --------
    # STEP 1: Receive notification from subscription; notification type: PAYMENT_UPDATED
    #
    # Other available notification types are: INVENTORY_UPDATED, TIMECARD_UPDATED
    # See: https://docs.connect.squareup.com/api/connect/v2#availablewebhookevents
    # -------
    if (property_exists($callbackBodyJson, 'event_type') and $callbackBodyJson->event_type == 'PAYMENT_UPDATED') {

      # Get the ID of the updated payment
      $paymentId = $callbackBodyJson->entity_id;

      # Get the ID of the payment's associated location
      $locationId = $callbackBodyJson->location_id;

      # Send a request to the Retrieve Payment endpoint to get the updated payment's full details
      # ------
      # STEP 2: Callback returns paymentId and locationId
      # Submit another Square API to retrieve the payment information
      $response = Unirest\Request::get($connectHost . '/v1/' . $locationId . '/payments/' . $paymentId, $requestHeaders);

      $responseJson = json_decode($response);

      # write paymentId, locationId to csv
      # ------
      # STEP 3: Describe how you want to do with the retrieved data because you already know the payment is updated at this point.
      # Things could be saving to a database or outputting to CSV ...
      #
      # Please refer to: https://docs.connect.squareup.com/api/connect/v2#endpoint-v1transactions-retrievepayment
      #
      # Under the Response fields, you should be able to find all the necessary fields for the payment. 
      # For instance: 
      #   - payment_url: String
      #   - itemizations: V1PaymentItemization[]
      # ------
      exportCSV('webhooks_' . date('Ymd') . '.csv', array(
     	'paymentId' => $paymentId, 
        'locationId' => $locationId,	
	'payment_url' => $responseJson->payment_url,
	'itemizations' => json_encode($responseJson->itemizations),
	// ...
	'callbackBody' => $callbackBody
      )); 

      # Perform an action based on the returned payment (in this case, simply log it)
      error_log(json_encode($response->body, JSON_PRETTY_PRINT));
    }
  } else {
    error_log("Received a non-POST request");
  }
}


function exportCSV($fileName, $data) {
  if (!is_array($data)) return; 

  $fp = fopen($fileName, 'w+');
  fputcsv($fp, $data); 
  fclose($fp);
}


# Validates HMAC-SHA1 signatures included in webhook notifications to ensure notifications came from Square
function isValidCallback($callbackBody, $callbackSignature) {
  global $webhookUrl, $webhookSignatureKey;

  # Combine your webhook notification URL and the JSON body of the incoming request into a single string
  $stringToSign = $webhookUrl . $callbackBody;

  # Generate the HMAC-SHA1 signature of the string, signed with your webhook signature key
  $stringSignature = base64_encode(hash_hmac('sha1', $stringToSign, $webhookSignatureKey, true));

  # Hash the signatures a second time (to protect against timing attacks)
  # and compare them
  return (sha1($stringSignature) === sha1($callbackSignature));
}

# Process the callback
webhookCallback();

