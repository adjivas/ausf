package context

import (
	"fmt"
	"os"
	"net/netip"

	"github.com/google/uuid"

	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func InitAusfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.InitLog.Infof("ausfconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	sbi := configuration.Sbi

	context.NfId = uuid.New().String()
	context.GroupID = configuration.GroupId
	context.NrfUri = configuration.NrfUri
	context.NrfCertPem = configuration.NrfCertPem
	context.UriScheme = models.UriScheme(configuration.Sbi.Scheme) // default uri scheme
	context.RegisterIP = factory.AusfSbiDefaultIP                  // default localhost
	context.SBIPort = factory.AusfSbiDefaultPort                   // default port
	if sbi != nil {
		if sbi.RegisterIP != "" {
			context.RegisterIP = sbi.RegisterIP
		}
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}

		if sbi.Scheme == "https" {
			context.UriScheme = models.UriScheme_HTTPS
		} else {
			context.UriScheme = models.UriScheme_HTTP
		}

		context.BindingIP = os.Getenv(sbi.BindingIP)
		if context.BindingIP != "" {
			logger.InitLog.Info("Parsing ServerIP address from ENV Variable.")
		} else {
			context.BindingIP = sbi.BindingIP
			if context.BindingIP == "" {
				logger.InitLog.Warn("Error parsing ServerIP address as string. Using the 0.0.0.0 address as default.")
				context.BindingIP = "0.0.0.0"
			}
		}
	}

	registerIP, _ := netip.ParseAddr(context.RegisterIP);
	sbiPort := uint16(context.SBIPort)
	context.Url = string(context.UriScheme) + "://" + netip.AddrPortFrom(registerIP, sbiPort).String()

	context.PlmnList = append(context.PlmnList, configuration.PlmnSupportList...)

	// context.NfService
	context.NfService = make(map[models.ServiceName]models.NfService)
	AddNfServices(&context.NfService, config, context)
	fmt.Println("ausf context = ", context)

	context.EapAkaSupiImsiPrefix = configuration.EapAkaSupiImsiPrefix
}

func AddNfServices(serviceMap *map[models.ServiceName]models.NfService, config *factory.Config, context *AUSFContext) {
	var nfService models.NfService
	var ipEndPoints []models.IpEndPoint
	var nfServiceVersions []models.NfServiceVersion
	services := *serviceMap

	// nausf-auth
	nfService.ServiceInstanceId = context.NfId
	nfService.ServiceName = models.ServiceName_NAUSF_AUTH

	var ipEndPoint models.IpEndPoint
	ipEndPoint.Ipv4Address = context.RegisterIP
	ipEndPoint.Port = int32(context.SBIPort)
	ipEndPoints = append(ipEndPoints, ipEndPoint)

	var nfServiceVersion models.NfServiceVersion
	nfServiceVersion.ApiFullVersion = config.Info.Version
	nfServiceVersion.ApiVersionInUri = "v1"
	nfServiceVersions = append(nfServiceVersions, nfServiceVersion)

	nfService.Scheme = context.UriScheme
	nfService.NfServiceStatus = models.NfServiceStatus_REGISTERED

	nfService.IpEndPoints = &ipEndPoints
	nfService.Versions = &nfServiceVersions
	services[models.ServiceName_NAUSF_AUTH] = nfService
}
