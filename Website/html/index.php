<?php
// Function to get the real IP address of the user
function getUserIP() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    return $_SERVER['REMOTE_ADDR'];
}

// Get the user's IP address
$user_ip = getUserIP();
echo "Your IP address is: " . $user_ip;

// Database connection settings
$servername = "db";  // Replace with your DB server address
$username = "root";  // Replace with your DB username
$password = "root_password";  // Replace with your DB password
$dbname = "mitre_database";  // Replace with your DB name

// Create database connection
$conn = new mysqli($servername, $username, $password, $dbname);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Elasticsearch server settings
$elasticsearchUrl = 'https://{ELASTIC_IP}:9200/wazuh-alerts*/_search?pretty';
$es_username = 'USERNAME';
$es_password = 'PASSWORD';

// Initialize cURL for Elasticsearch
$ch = curl_init($elasticsearchUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);  // Disable SSL verification (not recommended for production)
curl_setopt($ch, CURLOPT_USERPWD, $es_username . ':' . $es_password);
curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json'));
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);  // Disable hostname verification

// Elasticsearch query
$data = array(
    'query' => array(
        'bool' => array(
            'must' => array(
                array('match' => array('data.srcip' => '$user_ip'))
            ),
            'filter' => array(
                array('exists' => array('field' => 'rule.mitre'))
            )
        )
    )
);
$jsonData = json_encode($data);

curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonData);

// Execute Elasticsearch query
$response = curl_exec($ch);

if (curl_errno($ch)) {
    echo 'Error: ' . curl_error($ch);
} else {
    $decodedResponse = json_decode($response, true);

    if (isset($decodedResponse['hits']['hits']) && count($decodedResponse['hits']['hits']) > 0) {
        // Start the HTML table
        echo "<table border='1'>";
        echo "<tr><th>Timestamp</th><th>IP Address</th><th>Rule MITRE ID</th><th>Explanation</th></tr>";

        foreach ($decodedResponse['hits']['hits'] as $hit) {
            // Extract necessary data
            $ip = isset($hit['_source']['data']['ip']) ? $hit['_source']['data']['ip'] : 'N/A';
            $mitreId = isset($hit['_source']['rule']['mitre']['id']) ? implode(", ", (array)$hit['_source']['rule']['mitre']['id']) : 'N/A';
            $timestamp = isset($hit['_source']['@timestamp']) ? $hit['_source']['@timestamp'] : 'N/A';

            // Fetch explanation from the database or external script
            $explanation = 'N/A';
            if ($mitreId !== 'N/A') {
                $search_key = $mitreId;

                // Prepare SQL query to search for explanation
                $sql = "SELECT explanation FROM mitre_explanations WHERE id = ? LIMIT 1";
                $stmt = $conn->prepare($sql);
                $stmt->bind_param("s", $search_key);
                $stmt->execute();
                $result = $stmt->get_result();

                if ($row = $result->fetch_assoc()) {
                    if ($row["explanation"] !== ''){
                       $explanation = $row["explanation"];
                    }
                } else {
                    // Execute Python script for explanation
                    $command = escapeshellcmd('/usr/bin/python3 /var/www/html/OllamaAPI.py ' . escapeshellarg($mitreId));
                    $explanation = shell_exec($command);

                    // Insert the explanation into the database
                    $stmt = $conn->prepare(
                        "INSERT INTO mitre_explanations (id, explanation) VALUES (?, ?)
                        ON DUPLICATE KEY UPDATE explanation = VALUES(explanation)"
                    );
                    $stmt->bind_param("ss", $mitreId, $explanation);

                    if (!$stmt->execute()) {
                        echo "Error inserting/updating explanation: " . $stmt->error;
                    }
                }

                $stmt->close();
                $explanation = nl2br(htmlspecialchars($explanation));
            }

            // Output data in table rows
            echo "<tr>";
            echo "<td>{$timestamp}</td>";
            echo "<td>{$ip}</td>";
            echo "<td>{$mitreId}</td>";
            echo "<td>{$explanation}</td>";
            echo "</tr>";
        }

        // End the HTML table
        echo "</table>";
    } else {
        echo "No alerts found.";
    }
}

// Close cURL and database connection
curl_close($ch);
$conn->close();
?>
