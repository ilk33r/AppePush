//
//  MainPageViewController.h
//  ApplePush
//
//  Created by Ilker OZCAN on 31.08.2018.
//  Copyright © 2018 VeriPark. All rights reserved.
//

#import <Cocoa/Cocoa.h>

@interface MainPageViewController : NSViewController {
	@protected int _socket;
	@protected SSLContextRef _context;
}

@end
