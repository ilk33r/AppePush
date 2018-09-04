//
//  MainPageViewController.m
//  ApplePush
//
//  Created by Ilker OZCAN on 31.08.2018.
//  Copyright © 2018 VeriPark. All rights reserved.
//

#import "MainPageViewController.h"
#import "MainPageViewController+SendApns.h"

@interface MainPageViewController()

@property (nonatomic, unsafe_unretained) IBOutlet NSTextView *apnsMessage;
@property (nonatomic, weak) IBOutlet NSTextField *deviceToken;
@property (nonatomic, weak) IBOutlet NSProgressIndicator *indicator;
@property (nonatomic, weak) IBOutlet NSButton *isSandbox;
@property (nonatomic, weak) IBOutlet NSTextField *privateKeyPath;
@property (nonatomic, weak) IBOutlet NSSecureTextField *privateKeyPassword;
@property (nonatomic, assign) BOOL isSending;

@end

@implementation MainPageViewController

#pragma mark View Lifecycle

- (void)viewDidLoad {
	[super viewDidLoad];
	
	// Prepare UI
	[self prepareUI];
}

#pragma mark UI Methods

- (void)prepareUI {
	// Hide Indicator
	self.isSending = NO;
	[self.indicator setHidden:YES];
}

#pragma mark Actions

- (IBAction)selectFileCliecked:(NSButton *)sender {
	// Create the File Open Dialog class.
	NSOpenPanel* openDialog = [NSOpenPanel openPanel];
	
	// Enable the selection of files in the dialog.
	[openDialog setCanChooseFiles:YES];
	
	// Multiple files not allowed
	[openDialog setAllowsMultipleSelection:NO];
	
	// Can't select a directory
	[openDialog setCanChooseDirectories:NO];
	
	// Display the dialog. If the OK button was pressed, process the files.
	if ([openDialog runModal] == NSModalResponseOK) {
		// Get an array containing the files
		NSArray<NSURL *> *fileUrls = [openDialog URLs];
		
		// Check file selected
		if (fileUrls && fileUrls.count > 0) {
			// Then update private key path
			self.privateKeyPath.cell.title = fileUrls.firstObject.path;
		}
	}
}

- (IBAction)sendClicked:(NSButton *)sender {
	// Check notification is sending
	if (self.isSending) {
		// Do nothing
		return;
	}
	
	// Set sending
	self.isSending = YES;
	
	// Obtain values
	NSString *privateKeyPath = self.privateKeyPath.cell.title;
	NSString *password = self.privateKeyPassword.cell.title;
	NSString *token = self.deviceToken.cell.title;
	NSString *jsonData = self.apnsMessage.textStorage.string;
	BOOL isSandbox = (self.isSandbox.cell.state == NSControlStateValueOn) ? YES : NO;
	
	// Validate form
	if (token && token.length > 0 && jsonData && jsonData.length > 0 && privateKeyPath && privateKeyPath.length > 0) {
		// Weakify
		__weak typeof(self) weakSelf = self;
		
		// Handle notification callback
		void (^handleNotification)(BOOL, NSError *) = ^(BOOL status, NSError *error) {
			// Set sending
			weakSelf.isSending = NO;
			
			// Hide indicator
			[self.indicator stopAnimation:nil];
			[self.indicator setHidden:YES];
			
			if (!status) {
				// Display alert
				NSAlert *alert = [[NSAlert alloc] init];
				[alert setAlertStyle:NSAlertStyleCritical];
				[alert setMessageText:error.localizedDescription];
				[alert addButtonWithTitle:@"Ok"];
				[alert runModal];
			}
			else {
				// Display alert
				NSAlert *alert = [[NSAlert alloc] init];
				[alert setAlertStyle:NSAlertStyleInformational];
				[alert setMessageText:@"Push notification sended."];
				[alert addButtonWithTitle:@"Ok"];
				[alert runModal];
			}
			
			NSLog(@"handleNotification");
		};
		
		// Display indicator
		[self.indicator setHidden:NO];
		[self.indicator startAnimation:nil];
		
		// Send notification
		[self sendPushNotificationWithPrivateKeyPath:privateKeyPath
								  privateKeyPassword:password
										   isSandbox:isSandbox
											   token:token
											jsonData:jsonData
											callback:handleNotification];
	}
	else {
		// Set sending
		self.isSending = NO;
		
		// Display alert
		NSAlert *alert = [[NSAlert alloc] init];
		[alert setAlertStyle:NSAlertStyleCritical];
		[alert setMessageText:@"Invalid parameters."];
		[alert addButtonWithTitle:@"Ok"];
		[alert runModal];
	}
}

@end
