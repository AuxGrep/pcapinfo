package parsetypes

import (
	"github.com/activecm/rita/config"
)

// SSL provides a data structure for zeek's connection data
type SSL struct {
	// TimeStamp of this connection
	TimeStamp int64 `bson:"ts" bro:"ts" brotype:"time" json:"-"`
	// TimeStampGeneric is used when reading from json files
	TimeStampGeneric interface{} `bson:"-" json:"ts"`
	// UID is the Unique Id for this connection (generated by Bro)
	UID string `bson:"uid" bro:"uid" brotype:"string" json:"uid"`
	// Source is the source address for this connection
	Source string `bson:"id_orig_h" bro:"id.orig_h" brotype:"addr" json:"id.orig_h"`
	// SourcePort is the source port of this connection
	SourcePort int `bson:"id_orig_p" bro:"id.orig_p" brotype:"port" json:"id.orig_p"`
	// Destination is the destination of the connection
	Destination string `bson:"id_resp_h" bro:"id.resp_h" brotype:"addr" json:"id.resp_h"`
	// DestinationPort is the port at the destination host
	DestinationPort int `bson:"id_resp_p" bro:"id.resp_p" brotype:"port" json:"id.resp_p"`
	// VersionNum  : Numeric SSL/TLS version that the server chose
	VersionNum int `bson:"version_num" bro:"version_num" brotype:"count" json:"version_num"`
	// Version : SSL/TLS version that the server chose
	Version string `bson:"version" bro:"version" brotype:"string" json:"version"`
	// Cipher : SSL/TLS cipher suite that the server chose
	Cipher string `bson:"cipher" bro:"cipher" brotype:"string" json:"cipher"`
	// Curve : Elliptic curve the server chose when using ECDH/ECDHE
	Curve string `bson:"curve" bro:"curve" brotype:"string" json:"curve"`
	// ServerName : Value of the Server Name Indicator SSL/TLS extension.
	// It indicates the server name that the client was requesting.
	ServerName string `bson:"server_name" bro:"server_name" brotype:"string" json:"server_name"`
	// SessionID : Session ID offered by the client for session resumption.
	// Not used for logging.
	SessionID string `bson:"session_id" bro:"session_id" brotype:"string" json:"session_id"`
	// Resumed : Flag to indicate if the session was resumed reusing the key
	// material exchanged in an earlier connection
	Resumed bool `bson:"resumed" bro:"resumed" brotype:"bool" json:"resumed"`
	// ClientTicketEmptySessionSeen : Flag to indicate if we saw a non-empty
	// session ticket being sent by the client using an empty session ID.
	// This value is used to determine if a session is being resumed.
	// It’s not logged.  Note: may not be present in older bro versions.
	ClientTicketEmptySessionSeen bool `bson:"client_ticket_empty_session_seen" bro:"client_ticket_empty_session_seen" brotype:"bool" json:"client_ticket_empty_session_seen"`
	// ClientKeyExchangeSeen :Flag to indicate if we saw a client key exchange
	// message sent by the client. This value is used to determine if a session
	// is being resumed. It’s not logged.
	// Note: may not be present in older bro versions.
	ClientKeyExchangeSeen bool `bson:"client_key_exchange_seen" bro:"client_key_exchange_seen" brotype:"bool" json:"client_key_exchange_seen"`
	// ServerAppData : Count to track if the server already sent an application
	// data packet for TLS 1.3. Used to track when a session was established
	// Note: may not be present in older bro versions.
	ServerAppData int `bson:"server_appdata" bro:"server_appdata" brotype:"count" json:"server_appdata"`
	// ClientAppData : Flag to track if the client already sent an application
	// data packet for TLS 1.3. Used to track when a session was established
	// Note: may not be present in older bro versions.
	ClientAppData bool `bson:"client_appdata" bro:"client_appdata" brotype:"bool" json:"client_appdata"`
	// LastAlert : Last alert that was seen during the connection.
	LastAlert string `bson:"last_alert" bro:"last_alert" brotype:"string" json:"last_alert"`
	// NextProtocol : Next protocol the server chose using the application layer
	// next protocol extension, if present.
	NextProtocol string `bson:"next_protocol" bro:"next_protocol" brotype:"string" json:"next_protocol"`
	// AnalyzerID : The analyzer ID used for the analyzer instance attached to
	// each connection. It is not used for logging since it’s a meaningless
	// arbitrary number. Note: may not be present in older bro versions.
	AnalyzerID int `bson:"analyzer_id" bro:"analyzer_id" brotype:"count" json:"analyzer_id"`
	// Established : Flag to indicate if this ssl session has been established
	// successfully, or if it was aborted during the handshake
	Established bool `bson:"established" bro:"established" brotype:"bool" json:"established"`
	// Logged : Flag to indicate if this record already has been logged, to
	// prevent duplicates. Note: may not be present in older bro versions.
	Logged bool `bson:"logged" bro:"logged" brotype:"bool" json:"logged"`
	// CertChainFuids
	CertChainFuids []string `bson:"cert_chain_fuids" bro:"cert_chain_fuids" brotype:"vector[string]" json:"cert_chain_fuids"`
	// ClientCertChainFuids
	ClientCertChainFuids []string `bson:"client_cert_chain_fuids"  bro:"client_cert_chain_fuids" brotype:"vector[string]" json:"client_cert_chain_fuids"`
	// Subject
	Subject string `bson:"subject"  bro:"subject" brotype:"string" json:"subject"`
	// Issuer
	Issuer string `bson:"issuer"  bro:"issuer" brotype:"string" json:"issuer"`
	// ClientSubject
	ClientSubject string `bson:"client_subject"  bro:"client_subject" brotype:"string" json:"client_subject"`
	// ClientIssuer
	ClientIssuer string `bson:"client_issuer"  bro:"client_issuer" brotype:"string" json:"client_issuer"`
	// ValidationStatus
	ValidationStatus string `bson:"validation_status"  bro:"validation_status" brotype:"string" json:"validation_status"`
	// ValidationCode  : Numeric SSL/TLS version that the server chose
	ValidationCode int `bson:"validation_code" bro:"validation_code" brotype:"int" json:"validation_code"`
	// JA3 client hash
	JA3 string `bson:"ja3" bro:"ja3" brotype:"string" json:"ja3"`
	// JA3S server hash
	JA3S string `bson:"ja3s" bro:"ja3s" brotype:"string" json:"ja3s"`
	// AgentHostname names which sensor recorded this event. Only set when combining logs from multiple sensors.
	AgentHostname string `bson:"agent_hostname" bro:"agent_hostname" brotype:"string" json:"agent_hostname"`
	// AgentUUID identifies which sensor recorded this event. Only set when combining logs from multiple sensors.
	AgentUUID string `bson:"agent_uuid" bro:"agent_uuid" brotype:"string" json:"agent_uuid"`
}

//TargetCollection returns the mongo collection this entry should be inserted
func (line *SSL) TargetCollection(config *config.StructureTableCfg) string {
	return config.SSLTable
}

//ConvertFromJSON performs any extra conversions necessary when reading from JSON
func (line *SSL) ConvertFromJSON() {
	line.TimeStamp = convertTimestamp(line.TimeStampGeneric)
}