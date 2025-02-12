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
	context.SBIPort = factory.AusfSbiDefaultPort // default port
	context.RegisterIPv6 = func () string {
		if sbi.RegisterIPv6 != "" {
			return sbi.RegisterIPv6
		} else if sbi.RegisterIPv4 != "" {
			return ""
		} else {
			return factory.AusfSbiDefaultIPv6 // default uri scheme
		}
	}()
	context.RegisterIPv4 = func () string {
		if sbi.RegisterIPv6 != "" {
			return ""
		} else if sbi.RegisterIPv4 != "" {
			return sbi.RegisterIPv4
		} else {
			return factory.AusfSbiDefaultIPv6 // default uri scheme
		}
	}()
	if sbi != nil {
		if sbi.Port != 0 {
			context.SBIPort = sbi.Port
		}

		if sbi.Scheme == "https" {
			context.UriScheme = models.UriScheme_HTTPS
		} else {
			context.UriScheme = models.UriScheme_HTTP
		}

		context.BindingIPv6 = os.Getenv(sbi.BindingIPv6)
		if context.BindingIPv6 != "" {
			logger.InitLog.Info("Parsing ServerIPv6 address from ENV Variable.")
		} else {
			context.BindingIPv6 = sbi.BindingIPv6
			if context.BindingIPv6 == "" {
				context.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
				if context.BindingIPv4 != "" {
					logger.InitLog.Info("Parsing ServerIPv4 address from ENV Variable.")
				} else {
					context.BindingIPv4 = sbi.BindingIPv4
					if context.BindingIPv4 == "" {
						logger.InitLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
						context.BindingIPv4 = "0.0.0.0"
					}
				}
			}
		}
	}

	sbiPort := uint16(context.SBIPort)
	if context.RegisterIPv6 != "" {
		registerIPv6, _ := netip.ParseAddr(context.RegisterIPv6);
		context.Url = string(context.UriScheme) + "://" + netip.AddrPortFrom(registerIPv6, sbiPort).String()
	} else if context.RegisterIPv4 != "" {
		registerIPv4, _ := netip.ParseAddr(context.RegisterIPv4);
		context.Url = string(context.UriScheme) + "://" + netip.AddrPortFrom(registerIPv4, sbiPort).String()
	}

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
	ipEndPoint.Ipv4Address = context.RegisterIPv4
	ipEndPoint.Ipv6Address = context.RegisterIPv6
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
