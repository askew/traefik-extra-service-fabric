package servicefabric

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/containous/traefik/log"
	"github.com/containous/traefik/types"
	sf "github.com/jjcollinge/servicefabric"
	"golang.org/x/crypto/pkcs12"
)

// ServiceItemExtended provides a flattened view
// of the service with details of the application
// it belongs too and the replicas/partitions
type ServiceItemExtended struct {
	sf.ServiceItem
	Application sf.ApplicationItem
	Partitions  []PartitionItemExtended
	Labels      map[string]string
}

// PartitionItemExtended provides a flattened view
// of a services partitions
type PartitionItemExtended struct {
	sf.PartitionItem
	Replicas  []sf.ReplicaItem
	Instances []sf.InstanceItem
}

// sfClient is an interface for Service Fabric client's to implement.
// This is purposely a subset of the total Service Fabric API surface.
type sfClient interface {
	GetApplications() (*sf.ApplicationItemsPage, error)
	GetServices(appName string) (*sf.ServiceItemsPage, error)
	GetPartitions(appName, serviceName string) (*sf.PartitionItemsPage, error)
	GetReplicas(appName, serviceName, partitionName string) (*sf.ReplicaItemsPage, error)
	GetInstances(appName, serviceName, partitionName string) (*sf.InstanceItemsPage, error)
	GetServiceExtensionMap(service *sf.ServiceItem, app *sf.ApplicationItem, extensionKey string) (map[string]string, error)
	GetServiceLabels(service *sf.ServiceItem, app *sf.ApplicationItem, prefix string) (map[string]string, error)
	GetProperties(name string) (bool, map[string]string, error)
}

// replicaInstance interface provides a unified interface
// over replicas and instances
type replicaInstance interface {
	GetReplicaData() (string, *sf.ReplicaItemBase)
}

// ClientTLSSF is an extended version of the ClientTLS struct that has a parameter for the
// name of the CertificateRef in service fabric.
type ClientTLSSF struct {
	types.ClientTLS
	CertName string `description:"Name of the CertificateRef in the ContainerHostPolicies"`
}

// CreateTLSConfigFromSF creates a TLS config from ClientTLS structures
// https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-securing-containers
func (clientTLS *ClientTLSSF) CreateTLSConfigFromSF() (*tls.Config, error) {
	var err error
	if clientTLS == nil {
		log.Warnf("clientTLS is nil")
		return nil, nil
	}

	if len(clientTLS.CertName) > 0 {
		for _, element := range os.Environ() {
			variable := strings.Split(element, "=")

			if strings.HasPrefix(variable[0], "Certificates_") &&
				strings.HasSuffix(variable[0], clientTLS.CertName+"_PFX") {

				_, err = os.Stat(variable[1])

				if err != nil {
					return nil, fmt.Errorf("The certificate file does not exist. %s", err)
				}

				pfxData, err := ioutil.ReadFile(variable[1])

				if err != nil {
					return nil, fmt.Errorf("Error reading the certificate file. %s", err)
				}

				// Get the PFX password from the matching env variable
				pfxPwdVar := strings.Replace(variable[0], "_PFX", "_Password", 1)
				pfxPwd := os.Getenv(pfxPwdVar)

				blocks, err := pkcs12.ToPEM(pfxData, pfxPwd)
				if err != nil {
					return nil, fmt.Errorf("Error converting the certificate file. %s", err)
				}

				var pemData []byte
				for _, b := range blocks {
					pemData = append(pemData, pem.EncodeToMemory(b)...)
				}

				clientTLS.Cert = string(pemData)
				clientTLS.Key = string(pemData)
			}

			if strings.HasPrefix(variable[0], "Certificates_") &&
				strings.HasSuffix(variable[0], clientTLS.CertName+"_PEM") {

				// Get the private key from the matching env variable
				privKeyVar := strings.Replace(variable[0], "_PEM", "_PrivateKey", 1)
				privKey := os.Getenv(privKeyVar)

				clientTLS.Cert = string(variable[1])
				clientTLS.Key = string(privKey)
			}
		}
	}
	tlsConfig, err := clientTLS.CreateTLSConfig()
	return tlsConfig, err
}
