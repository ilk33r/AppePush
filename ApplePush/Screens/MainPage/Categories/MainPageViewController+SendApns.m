//
//  MainPageViewController+SendApns.m
//  ApplePush
//
//  Created by Ilker OZCAN on 3.09.2018.
//  Copyright © 2018 VeriPark. All rights reserved.
//

#include <netdb.h>
#import <Security/Authorization.h>
#import <ServiceManagement/ServiceManagement.h>
#import "MainPageViewController+SendApns.h"
#import "NSString+Hex.h"

@implementation MainPageViewController (SendApns)

#pragma mark SSL Read And Write Functions

OSStatus ApnsSSLRead(SSLConnectionRef connection, void *data, size_t *length);
OSStatus ApnsSSLWrite(SSLConnectionRef connection, const void *data, size_t *length);

#pragma mark Constants

NSString * const ApplePushProductionAddress = @"gateway.push.apple.com";
NSString * const ApplePushSandboxAddress = @"gateway.sandbox.push.apple.com";
NSInteger const ApplePushPort = 2195;

#pragma mark Apns Methods

- (void)sendPushNotificationWithPrivateKeyPath:(NSString *)privateKeyPath
							privateKeyPassword:(NSString *)privateKeyPassword
									 isSandbox:(BOOL)isSandbox
										 token:(NSString *)token
									  jsonData:(NSString *)jsonData
									  callback:(SendNotificationCallback)closure {
	// Create host
	NSString *host;
	
	// Check server is sandbox
	if (isSandbox) {
		host = ApplePushSandboxAddress;
	}
	else {
		host = ApplePushProductionAddress;
	}
	
	// Create settings
	CFArrayRef certificates = [self getCertificateRefFromFile:privateKeyPath password:privateKeyPassword];
	SecIdentityRef certificateIdentity = [self getCertificateIdentity:certificates];
	
	// Check socket connection is not success
	if (![self connectToHost:host callback:closure]) {
		// Then close connection
		[self disconnect];
		[self releaseCertificateItems:certificates];
		return;
	}
	
	// Check ssl connection is not success
	if (![self connectSSLWithHost:host identity:certificateIdentity callback:closure]) {
		// Then close connection
		[self disconnect];
		[self releaseCertificateItems:certificates];
		return;
	}
	
	// Check ssl handshake is not success
	if (![self handshakeSSLWithCallback:closure]) {
		// Then close connection
		[self disconnect];
		[self releaseCertificateItems:certificates];
		return;
	}
	
	// Obtain payload data
	NSData *payloadData = [self apnsMessageWithPayload:jsonData token:token];
	NSUInteger payloadLength = payloadData.length;
	__block NSError *error;
	
	// Write payload to apns server
	if ([self write:payloadData length:&payloadLength error:&error]) {
		// Read response
		NSMutableData *data = [NSMutableData dataWithLength:sizeof(uint8_t) * 2 + sizeof(uint32_t)];
		NSUInteger length = 0;
			
		if ([self read:data length:&length error:&error]) {
			dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
				uint8_t command = 0;
				[data getBytes:&command range:NSMakeRange(0, 1)];
				if (command == 0) {
					closure(YES, nil);
				}
				else if (command != 8) {
					NSError *err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:14 userInfo:@{NSLocalizedDescriptionKey: @"Invalid apns response." }];
					closure(NO, err);
				}
				else {
					uint8_t status = 0;
					[data getBytes:&status range:NSMakeRange(1, 1)];
					NSError *err;
					switch (status) {
						case 1:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNProcessing" }];
							break;
						case 2:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNMissingDeviceToken" }];
							break;
						case 3:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNMissingTopic" }];
							break;
						case 4:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNMissingPayload" }];
							break;
						case 5:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNInvalidTokenSize" }];
							break;
						case 6:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNInvalidTopicSize" }];
							break;
						case 7:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNInvalidPayloadSize" }];
							break;
						case 8:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNInvalidTokenContent" }];
							break;
						case 10:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNShutdown" }];
							break;
						default:
							err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:15 userInfo:@{NSLocalizedDescriptionKey: @"ErrorAPNUnknownErrorCode" }];
							break;
					}
					
					if (err) {
						closure(NO, err);
					}
				}
			});
		}
		else {
			NSError *err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:12 userInfo:@{NSLocalizedDescriptionKey: [error.localizedDescription copy] }];
			closure(NO, err);
		}
	}
	else {
		NSError *err = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:13 userInfo:@{NSLocalizedDescriptionKey: [error.localizedDescription copy] }];
		closure(NO, err);
	}
	
	// Then close connection
	[self disconnect];
	[self releaseCertificateItems:certificates];
}

- (BOOL)connectToHost:(NSString *)hostName
			 callback:(SendNotificationCallback)closure {
	// Create a socket
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:1 userInfo:@{NSLocalizedDescriptionKey: @"Could not create a socket."}];
		closure(NO, error);
		return NO;
	}
	
	// Create a host
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(struct sockaddr_in));
	struct hostent *entr = gethostbyname(hostName.UTF8String);
	if (!entr) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:2 userInfo:@{NSLocalizedDescriptionKey: @"Could not resolve a hostname."}];
		closure(NO, error);
		return NO;
	}
	
	// Set port
	struct in_addr host;
	memcpy(&host, entr->h_addr, sizeof(struct in_addr));
	addr.sin_addr = host;
	addr.sin_port = htons((u_short)ApplePushPort);
	addr.sin_family = AF_INET;
	
	// Connect to socket
	int conn = connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
	if (conn < 0) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:3 userInfo:@{NSLocalizedDescriptionKey: @"Could not connect to host."}];
		closure(NO, error);
		return NO;
	}
	
	// Create a socket control file
	int cntl = fcntl(sock, F_SETFL, O_NONBLOCK);
	if (cntl < 0) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:4 userInfo:@{NSLocalizedDescriptionKey: @"Could not create a socket file."}];
		closure(NO, error);
		return NO;
	}
	
	// Setup socket options
	int set = 1, sopt = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
	if (sopt < 0) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:5 userInfo:@{NSLocalizedDescriptionKey: @"Could not set socket options."}];
		closure(NO, error);
		return NO;
	}
	
	// Keep socket
	_socket = sock;
	return YES;
}

- (BOOL)connectSSLWithHost:(NSString *)hostName
				  identity:(SecIdentityRef)identity
				  callback:(SendNotificationCallback)closure {
	// Create ssl context
	SSLContextRef context = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
	if (!context) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:6 userInfo:@{NSLocalizedDescriptionKey: @"Could not create ssl context."}];
		closure(NO, error);
		return NO;
	}
	
	// Set ssl input output functions
	OSStatus setio = SSLSetIOFuncs(context, ApnsSSLRead, ApnsSSLWrite);
	if (setio != errSecSuccess) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:7 userInfo:@{NSLocalizedDescriptionKey: @"Could not set ssl input and output."}];
		closure(NO, error);
		return NO;
	}
	
	// Setup connection
	OSStatus setconn = SSLSetConnection(context, (SSLConnectionRef)(NSInteger)_socket);
	if (setconn != errSecSuccess) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:8 userInfo:@{NSLocalizedDescriptionKey: @"Could not set ssl connection."}];
		closure(NO, error);
		return NO;
	}
	
	// Setup peer
	OSStatus setpeer = SSLSetPeerDomainName(context, hostName.UTF8String, strlen(hostName.UTF8String));
	if (setpeer != errSecSuccess) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:9 userInfo:@{NSLocalizedDescriptionKey: @"Could not set ssl peer name."}];
		closure(NO, error);
		return NO;
	}
	
	// Set certificate to context
	OSStatus setcert = SSLSetCertificate(context, (__bridge CFArrayRef)@[(__bridge id)identity]);
	if (setcert != errSecSuccess) {
		NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:10 userInfo:@{NSLocalizedDescriptionKey: @"Could not set ssl certificate."}];
		closure(NO, error);
		return NO;
	}
	
	// Keep context
	_context = context;
	return YES;
}

- (BOOL)handshakeSSLWithCallback:(SendNotificationCallback)closure {
	OSStatus status = errSSLWouldBlock;
	for (NSUInteger i = 0; i < (1 << 26) && status == errSSLWouldBlock; i++) {
		status = SSLHandshake(_context);
	}
	
	// Check statıus
	if (status == errSecSuccess) {
		return YES;
	}
	
	NSError *error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:status userInfo:@{NSLocalizedDescriptionKey: @"SSL handshake error."}];
	closure(NO, error);
	return NO;
}

#pragma mark Helper Methods

- (NSData *)apnsMessageWithPayload:(NSString *)payload token:(NSString *)token {
	// Create buffer with following payload
	// Payload format 0 + 0 + 32 + Token Size + Token + 0 + Payload
	char buffer[sizeof(uint8_t) + sizeof(uint32_t) * 2 + sizeof(uint16_t) + 32 + sizeof(uint16_t) + payload.length];
	char *p = buffer;
	
	// Add 0 to buffer
	uint8_t command = 0;
	memcpy(p, &command, sizeof(uint8_t));
	p += sizeof(uint8_t);
	
	// Create token data
	NSData *tokenData = [token dataFromHex];
	
	// Add token length to data
	uint16_t tokenLength = htons(tokenData.length);
	memcpy(p, &tokenLength, sizeof(uint16_t));
	p += sizeof(uint16_t);
	
	// Append token to payload
	memcpy(p, tokenData.bytes, tokenData.length);
	p += tokenData.length;
	
	// Trim payload
	NSString *trimmedPayload = [[[payload stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]
								  ] stringByReplacingOccurrencesOfString:@"\t" withString:@""
								 ] stringByReplacingOccurrencesOfString:@"\n" withString:@""];
	NSData *payloadData = [trimmedPayload dataUsingEncoding:NSUTF8StringEncoding];
	
	// Append payload size
	uint16_t payloadLength = htons(payloadData.length);
	memcpy(p, &payloadLength, sizeof(uint16_t));
	p += sizeof(uint16_t);
	
	// Append payload
	memcpy(p, payloadData.bytes, payloadData.length);
	p += payloadData.length;
	
	return [NSData dataWithBytes:buffer length:p - buffer];
}

- (void)disconnect {
	// Close ssl connection
	if (_context) {
		SSLClose(_context);
	}
	
	// Check socket is connected
	if (_socket >= 0) {
		// Then close socket
		close(_socket);
		_socket = -1;
	}
	
	// Release ssl context
	if (_context) {
		CFRelease(_context);
		_context = NULL;
	}
}

- (CFArrayRef)getCertificateRefFromFile:(NSString *)certificateFile password:(NSString *)password {
	// Obtain certificate data
	NSURL *fileUrl = [NSURL fileURLWithPath:certificateFile];
	NSError *error;
	NSData *certData = [NSData dataWithContentsOfURL:fileUrl options:NSDataReadingMappedIfSafe error:&error];
	
	// Create certificate
	NSDictionary *certificateOptions = @{ (__bridge NSString *)kSecImportExportPassphrase: password };
	CFArrayRef items;
	OSStatus pkcs12Status = SecPKCS12Import((__bridge CFDataRef)certData, (__bridge CFDictionaryRef)certificateOptions, &items);
	
	// Check status
	if (pkcs12Status == errSecSuccess) {
		return items;
	}
	
	return nil;
}

- (SecIdentityRef)getCertificateIdentity:(CFArrayRef)items {
	// Convert items to array
	NSArray *itemsArray = (__bridge NSArray *)items;
	
	// Loop throught items
	for (NSDictionary *itemData in itemsArray) {
		SecIdentityRef identity = (__bridge SecIdentityRef)([itemData objectForKey:(__bridge NSString *)kSecImportItemIdentity]);
		if (identity) {
			return identity;
		}
	}
	
	return NULL;
}

- (void)releaseCertificateItems:(CFArrayRef)items {
	CFRelease(items);
}

#pragma mark - Read Write

- (BOOL)read:(NSMutableData *)data length:(NSUInteger *)length error:(NSError *__autoreleasing *)error {
	*length = 0;
	size_t processed = 0;
	OSStatus status = SSLRead(_context, data.mutableBytes, data.length, &processed);
	*length = processed;
	switch (status) {
		case errSecSuccess:
			return YES;
		case errSSLWouldBlock:
			return YES;
		default:
			*error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:11 userInfo:@{NSLocalizedDescriptionKey: @"SSL read error."}];
			return NO;
	}
}

- (BOOL)write:(NSData *)data length:(NSUInteger *)length error:(NSError *__autoreleasing *)error {
	*length = 0;
	size_t processed = 0;
	OSStatus status = SSLWrite(_context, data.bytes, data.length, &processed);
	*length = processed;
	switch (status) {
		case errSecSuccess:
			return YES;
		case errSSLWouldBlock:
			return YES;
		default:
			*error = [NSError errorWithDomain:NSStreamSOCKSErrorDomain code:11 userInfo:@{NSLocalizedDescriptionKey: @"SSL write error."}];
			return NO;
	}
}

OSStatus ApnsSSLRead(SSLConnectionRef connection, void *data, size_t *length) {
	size_t leng = *length;
	*length = 0;
	size_t read = 0;
	ssize_t rcvd = 0;
	for(; read < leng; read += rcvd) {
		rcvd = recv((int)connection, (char *)data + read, leng - read, 0);
		if (rcvd <= 0) break;
	}
	*length = read;
	if (rcvd > 0 || !leng) {
		return errSecSuccess;
	}
	if (!rcvd) {
		return errSSLClosedGraceful;
	}
	switch (errno) {
		case EAGAIN: return errSSLWouldBlock;
		case ECONNRESET: return errSSLClosedAbort;
	}
	return errSecIO;
}

OSStatus ApnsSSLWrite(SSLConnectionRef connection, const void *data, size_t *length) {
	size_t leng = *length;
	*length = 0;
	size_t sent = 0;
	ssize_t wrtn = 0;
	for (; sent < leng; sent += wrtn) {
		wrtn = write((int)connection, (char *)data + sent, leng - sent);
		if (wrtn <= 0) break;
	}
	*length = sent;
	if (wrtn > 0 || !leng) {
		return errSecSuccess;
	}
	switch (errno) {
		case EAGAIN: return errSSLWouldBlock;
		case EPIPE: return errSSLClosedAbort;
	}
	return errSecIO;
}

@end
