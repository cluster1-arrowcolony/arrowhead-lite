package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const baseURL = "http://localhost:8443/api/v1"

type MyNode struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type MyService struct {
	ID         string `json:"id,omitempty"`
	Name       string `json:"name"`
	NodeID     string `json:"node_id,omitempty"`
	Definition string `json:"definition"`
	URI        string `json:"uri"`
	Method     string `json:"method"`
}

type RegistrationRequest struct {
	Node    MyNode    `json:"node"`
	Service MyService `json:"service,omitempty"`
}

type AuthRule struct {
	ConsumerID string `json:"consumer_id"`
	ProviderID string `json:"provider_id"`
	ServiceID  string `json:"service_id"`
}

type OrchestrationRequest struct {
	RequesterID string `json:"requester_id"`
	ServiceName string `json:"service_name"`
}

func main() {
	fmt.Println("🚀 Arrowhead IoT Service Mesh Example")
	fmt.Println("=====================================")

	// Step 1: Register provider node
	fmt.Println("\n1. Registering provider node...")
	provider := registerNode("temperature-provider", "192.168.1.100", 8080)
	fmt.Printf("   ✓ Provider registered: %s\n", provider.ID)

	// Step 2: Register consumer node
	fmt.Println("\n2. Registering consumer node...")
	consumer := registerNode("temperature-consumer", "192.168.1.101", 8081)
	fmt.Printf("   ✓ Consumer registered: %s\n", consumer.ID)

	// Step 3: Generate token for provider
	fmt.Println("\n3. Generating authentication token...")
	token := generateToken(provider.ID)
	fmt.Printf("   ✓ Token generated: %s...\n", token[:20])

	// Step 4: Register service
	fmt.Println("\n4. Registering temperature service...")
	service := registerService(provider.ID, token)
	fmt.Printf("   ✓ Service registered: %s\n", service.ID)

	// Step 5: Create authorization rule
	fmt.Println("\n5. Creating authorization rule...")
	createAuthRule(consumer.ID, provider.ID, service.ID, token)
	fmt.Printf("   ✓ Authorization rule created\n")

	// Step 6: Perform orchestration
	fmt.Println("\n6. Performing service orchestration...")
	orchestrate(consumer.ID, "temperature-sensor", token)
	fmt.Printf("   ✓ Service discovery completed\n")

	// Step 7: Publish event
	fmt.Println("\n7. Publishing temperature event...")
	publishEvent(provider.ID, token)
	fmt.Printf("   ✓ Event published\n")

	// Step 8: Check node metrics
	fmt.Println("\n8. Checking node metrics...")
	checkMetrics()

	fmt.Println("\n🎉 Example completed successfully!")
	fmt.Println("   Visit http://localhost:8443 to see the dashboard")
}

func registerNode(name, address string, port int) MyNode {
	req := RegistrationRequest{
		Node: MyNode{
			Name:    name,
			Address: address,
			Port:    port,
		},
	}

	body, _ := json.Marshal(req)
	resp, err := http.Post(baseURL+"/registry/nodes", "application/json", bytes.NewBuffer(body))
	if err != nil {
		panic(fmt.Sprintf("Failed to register node: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		bodyBytes, _ := io.ReadAll(resp.Body)
		panic(fmt.Sprintf("Failed to register node: %s", string(bodyBytes)))
	}

	var node MyNode
	json.NewDecoder(resp.Body).Decode(&node)
	return node
}

func generateToken(nodeID string) string {
	// For this example, we'll use a simple approach
	// In real usage, you'd need proper authentication
	return "demo-token-" + nodeID
}

func registerService(nodeID, token string) MyService {
	req := RegistrationRequest{
		Service: MyService{
			Name:       "temperature-sensor",
			NodeID:     nodeID,
			Definition: "temperature-reading",
			URI:        "/api/temperature",
			Method:     "GET",
		},
	}

	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", baseURL+"/registry/services", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		panic(fmt.Sprintf("Failed to register service: %v", err))
	}
	defer resp.Body.Close()

	var service MyService
	json.NewDecoder(resp.Body).Decode(&service)
	return service
}

func createAuthRule(consumerID, providerID, serviceID, token string) {
	rule := AuthRule{
		ConsumerID: consumerID,
		ProviderID: providerID,
		ServiceID:  serviceID,
	}

	body, _ := json.Marshal(rule)
	httpReq, _ := http.NewRequest("POST", baseURL+"/auth/rules", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		panic(fmt.Sprintf("Failed to create auth rule: %v", err))
	}
	defer resp.Body.Close()
}

func orchestrate(requesterID, serviceName, token string) {
	req := OrchestrationRequest{
		RequesterID: requesterID,
		ServiceName: serviceName,
	}

	body, _ := json.Marshal(req)
	httpReq, _ := http.NewRequest("POST", baseURL+"/orchestration/", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		panic(fmt.Sprintf("Failed to orchestrate: %v", err))
	}
	defer resp.Body.Close()
}

func publishEvent(publisherID, token string) {
	event := map[string]interface{}{
		"type":  "sensor-reading",
		"topic": "temperature",
		"payload": map[string]interface{}{
			"temperature": 23.5,
			"unit":        "celsius",
			"timestamp":   time.Now().Format(time.RFC3339),
		},
	}

	body, _ := json.Marshal(event)
	httpReq, _ := http.NewRequest("POST", baseURL+"/events/publish", bytes.NewBuffer(body))
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(httpReq)
	if err != nil {
		panic(fmt.Sprintf("Failed to publish event: %v", err))
	}
	defer resp.Body.Close()
}

func checkMetrics() {
	resp, err := http.Get(baseURL + "/metrics")
	if err != nil {
		panic(fmt.Sprintf("Failed to get metrics: %v", err))
	}
	defer resp.Body.Close()

	var metrics map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&metrics)

	fmt.Printf("   • Total Nodes: %.0f\n", metrics["total_nodes"])
	fmt.Printf("   • Total Services: %.0f\n", metrics["total_services"])
	fmt.Printf("   • Total Events: %.0f\n", metrics["total_events"])
}
