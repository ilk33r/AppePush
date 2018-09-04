//
//  NSString+Hex.m
//  ApplePush
//
//  Created by Ilker OZCAN on 4.09.2018.
//  Copyright © 2018 VeriPark. All rights reserved.
//

#import "NSString+Hex.h"

@implementation NSString (Hex)

- (NSData *)dataFromHex {
	NSMutableData *result = [[NSMutableData alloc] init];
	char buffer[3] = {'\0','\0','\0'};
	for (NSUInteger i = 0; i < self.length / 2; i++) {
		buffer[0] = [self characterAtIndex:i * 2];
		buffer[1] = [self characterAtIndex:i * 2 + 1];
		unsigned char b = strtol(buffer, NULL, 16);
		[result appendBytes:&b length:1];
	}
	return result;
}

@end
