//
//  MainPageViewController+SendApns.h
//  ApplePush
//
//  Created by Ilker OZCAN on 3.09.2018.
//  Copyright © 2018 VeriPark. All rights reserved.
//

#import "MainPageViewController.h"

typedef void (^SendNotificationCallback) (BOOL, NSError *);

@interface MainPageViewController (SendApns)

#pragma mark Apns Methods

- (void)sendPushNotificationWithPrivateKeyPath:(NSString *)privateKeyPath
							privateKeyPassword:(NSString *)privateKeyPassword
									 isSandbox:(BOOL)isSandbox
										 token:(NSString *)token
									  jsonData:(NSString *)jsonData
									  callback:(SendNotificationCallback)closure;

#pragma mark - Read Write

- (BOOL)read:(NSMutableData *)data length:(NSUInteger *)length error:(NSError *__autoreleasing *)error;
- (BOOL)write:(NSData *)data length:(NSUInteger *)length error:(NSError *__autoreleasing *)error;

@end
