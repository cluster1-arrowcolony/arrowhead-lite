package pkg_test

import (
	"fmt"
	"time"

	"git.ri.se/eu-cop-pilot/arrowhead-lite/pkg"
)

// Example_systemRegistration demonstrates how to create a system registration request.
// This is the first step for any IoT device or application joining the Arrowhead local cloud.
func Example_systemRegistration() {
	registration := pkg.SystemRegistration{
		SystemName:         "temperature-sensor-001",
		Address:            "192.168.1.100",
		Port:               8080,
		AuthenticationInfo: "", // Empty for development mode, certificate thumbprint for production
		Metadata: map[string]string{
			"location": "building-a-floor-2",
			"type":     "temperature",
		},
	}

	fmt.Printf("System: %s at %s:%d\n", registration.SystemName, registration.Address, registration.Port)
	// Output: System: temperature-sensor-001 at 192.168.1.100:8080
}

// Example_serviceRegistration demonstrates how to register a service.
// Services define capabilities that provider systems offer to consumers.
func Example_serviceRegistration() {
	serviceReg := pkg.ServiceRegistrationRequest{
		ServiceDefinition: "temperature-data",
		ProviderSystem: pkg.ProviderSystem{
			SystemName:         "temperature-sensor-001",
			Address:            "192.168.1.100",
			Port:               8080,
			AuthenticationInfo: "",
		},
		ServiceUri: "/api/temperature",
		Secure:     "TOKEN",
		Version:    "1",
		Interfaces: []string{"HTTP-SECURE-JSON"},
		Metadata: map[string]string{
			"unit":     "celsius",
			"accuracy": "0.1",
		},
	}

	fmt.Printf("Service: %s via %s\n", serviceReg.ServiceDefinition, serviceReg.Interfaces[0])
	// Output: Service: temperature-data via HTTP-SECURE-JSON
}

// Example_orchestrationRequest demonstrates how to request service orchestration.
// Orchestration is used to discover and get recommendations for service providers.
func Example_orchestrationRequest() {
	orchRequest := pkg.OrchestrationRequest{
		RequesterSystem: pkg.RequesterSystem{
			SystemName: "data-collector",
			Address:    "192.168.1.200",
			Port:       8081,
		},
		RequestedService: pkg.RequestedService{
			ServiceDefinitionRequirement: "temperature-data",
			InterfaceRequirements:        []string{"HTTP-SECURE-JSON"},
			SecurityRequirements:         []string{"TOKEN"},
		},
		OrchestrationFlags: pkg.OrchestrationFlags{
			Matchmaking:    true,
			MetadataSearch: true,
		},
	}

	fmt.Printf("Requesting: %s from %s\n",
		orchRequest.RequestedService.ServiceDefinitionRequirement,
		orchRequest.RequesterSystem.SystemName)
	// Output: Requesting: temperature-data from data-collector
}

// Example_authorizationRule demonstrates creating an authorization rule.
// Authorization rules define which consumer systems can access which provider services.
func Example_authorizationRule() {
	authReq := pkg.AddAuthorizationRequest{
		ConsumerID:           1,           // Database ID of the consumer system
		ProviderIDs:          []int{2, 3}, // Database IDs of allowed providers
		ServiceDefinitionIDs: []int{5},    // Database ID of the service definition
		InterfaceIDs:         []int{1},    // Database ID of the interface
	}

	fmt.Printf("Authorizing consumer %d to access %d providers\n",
		authReq.ConsumerID, len(authReq.ProviderIDs))
	// Output: Authorizing consumer 1 to access 2 providers
}

// Example_serviceWithExpiration demonstrates how to register a service with an expiration time.
// This is useful for temporary services or services with known lifecycle limits.
func Example_serviceWithExpiration() {
	expirationTime := time.Now().Add(24 * time.Hour)

	serviceReg := pkg.ServiceRegistrationRequest{
		ServiceDefinition: "temporary-storage",
		ProviderSystem: pkg.ProviderSystem{
			SystemName: "storage-node-temp",
			Address:    "192.168.1.150",
			Port:       9000,
		},
		ServiceUri:    "/api/store",
		EndOfValidity: expirationTime.Format(time.RFC3339),
		Secure:        "TOKEN",
		Version:       "1",
		Interfaces:    []string{"HTTP-SECURE-JSON"},
	}

	fmt.Printf("Service expires: %s\n", serviceReg.EndOfValidity[:10])
	// The output will vary based on current date, so we skip exact matching
}

// Example_metadataFiltering demonstrates how to use metadata in orchestration requests
// to find services with specific characteristics.
func Example_metadataFiltering() {
	orchRequest := pkg.OrchestrationRequest{
		RequesterSystem: pkg.RequesterSystem{
			SystemName: "hvac-controller",
			Address:    "192.168.1.250",
			Port:       8082,
		},
		RequestedService: pkg.RequestedService{
			ServiceDefinitionRequirement: "temperature-data",
			InterfaceRequirements:        []string{"HTTP-SECURE-JSON"},
			MetadataRequirements: map[string]string{
				"location": "building-a-floor-2",
				"unit":     "celsius",
			},
		},
		OrchestrationFlags: pkg.OrchestrationFlags{
			MetadataSearch: true, // Enable metadata-based filtering
		},
	}

	fmt.Printf("Searching for services with %d metadata filters\n",
		len(orchRequest.RequestedService.MetadataRequirements))
	// Output: Searching for services with 2 metadata filters
}

// Example_versionRequirements demonstrates how to specify version constraints
// when requesting services through orchestration.
func Example_versionRequirements() {
	minVersion := 2
	maxVersion := 5

	orchRequest := pkg.OrchestrationRequest{
		RequesterSystem: pkg.RequesterSystem{
			SystemName: "analytics-service",
			Address:    "192.168.1.201",
			Port:       8083,
		},
		RequestedService: pkg.RequestedService{
			ServiceDefinitionRequirement: "sensor-api",
			InterfaceRequirements:        []string{"HTTP-SECURE-JSON"},
			MinVersionRequirement:        &minVersion,
			MaxVersionRequirement:        &maxVersion,
		},
		OrchestrationFlags: pkg.OrchestrationFlags{
			Matchmaking: true,
		},
	}

	fmt.Printf("Requesting service versions %d-%d\n",
		*orchRequest.RequestedService.MinVersionRequirement,
		*orchRequest.RequestedService.MaxVersionRequirement)
	// Output: Requesting service versions 2-5
}
