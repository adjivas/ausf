package context

import (
	"fmt"
	"os"
	"net"
	"net/netip"

	"github.com/google/uuid"

	"github.com/free5gc/ausf/internal/logger"
	"github.com/free5gc/ausf/pkg/factory"
	"github.com/free5gc/openapi/models"
)

func RegisterAddr(registerIP string) netip.Addr {
	ips, err := net.LookupIP(registerIP)
	if err != nil {
		logger.InitLog.Errorf("Resolve RegisterIP hostname %s failed: %+v", registerIP, err)
	}
	ip, _ := netip.ParseAddr(ips[0].String());
	return ip
}

func InitAusfContext(context *AUSFContext) {
	config := factory.AusfConfig
	logger.InitLog.Infof("ausfconfig Info: Version[%s] Description[%s]\n", config.Info.Version, config.Info.Description)

	configuration := config.Configuration
	sbi := configuration.Sbi

	context.NfId = uuid.New().String()
	context.GroupID = configuration.GroupId
	context.NrfUri = configuration.NrfUri
	context.NrfCertPem = configuration.NrfCertPem

	if sbi.RegisterIP != "" {
		context.RegisterIP = sbi.RegisterIP
	} else if sbi.RegisterIPv4 != "" {
		context.RegisterIP =  sbi.RegisterIPv4
	} else {
		context.RegisterIP = factory.AusfSbiDefaultIPv4 // default uri scheme
	}

	if sbi.Port != 0 {
		context.SBIPort = sbi.Port
	} else {
		context.SBIPort = factory.AusfSbiDefaultPort // default port
	}

	if sbi.Scheme == "https" {
		context.UriScheme = models.UriScheme_HTTPS
	} else {
		context.UriScheme = models.UriScheme_HTTP
	}

	if bindingIP := os.Getenv(sbi.BindingIP); bindingIP != "" {
		context.BindingIP = bindingIP;
		logger.InitLog.Info("Parsing ServerIP address from ENV Variable.")
	} else if bindingIP := sbi.BindingIP; bindingIP != "" {
		context.BindingIP = bindingIP;
	} else if bindingIPv4 := os.Getenv(sbi.BindingIPv4); bindingIPv4 != "" {
		context.BindingIP = bindingIPv4;
		logger.InitLog.Info("Parsing ServerIPv4 address from ENV Variable.")
	} else if bindingIPv4 := sbi.BindingIPv4; bindingIPv4 != "" {
		context.BindingIP = bindingIPv4;
	} else {
		logger.InitLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
		context.BindingIP = "0.0.0.0"
	}

	sbiRegisterIp := RegisterAddr(context.RegisterIP)
	sbiPort := uint16(context.SBIPort)

	context.Url = string(context.UriScheme) + "://" + netip.AddrPortFrom(sbiRegisterIp, sbiPort).String()
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
	ipEndPoint.Port = int32(context.SBIPort)
	ipEndPoints = append(ipEndPoints, ipEndPoint)

	registerAddr := RegisterAddr(context.RegisterIP)
	if registerAddr.Is6() {
		ipEndPoint.Ipv6Address = context.RegisterIP
	} else if registerAddr.Is4() {
		ipEndPoint.Ipv4Address = context.RegisterIP
	}

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
