//
// Copyright 2025 voidtools / David Carpenter
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

// Everything server
// port 14630 derived from 'index'
// 14501-14935 Unassigned

// TODO:
// allow only 3-5 attempts to login. after that add a 5 minute delay. (per IP)
// db for each user

#define _WIN32_IE 0x0501
#define _WIN32_WINNT 0x0501
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include "..\..\include\everything_plugin.h"
#include "version.h"
#include <Wincrypt.h>

//DEBUG_FIXME("differentiate between config user and server user");

#define EVERYTHING_SERVER_CLIENT_STATE_CONNECT			0
#define EVERYTHING_SERVER_CLIENT_STATE_LOGIN_COMMAND	1
#define EVERYTHING_SERVER_CLIENT_STATE_LOGIN_DATA		2
#define EVERYTHING_SERVER_CLIENT_STATE_READ_COMMAND		3
#define EVERYTHING_SERVER_CLIENT_STATE_READ_DATA		4
#define EVERYTHING_SERVER_CLIENT_STATE_SEND_REPLY		5
#define EVERYTHING_SERVER_CLIENT_STATE_ERROR			6
#define EVERYTHING_SERVER_CLIENT_STATE_SEND_INDEX		7
#define EVERYTHING_SERVER_CLIENT_STATE_SEND_JOURNAL		8

#define EVERYTHING_SERVER_MAX_RECV_SIZE					(272)
#define EVERYTHING_SERVER_MAX_SEND_SIZE					(65536)

#define EVERYTHING_SERVER_JOURNAL_ITEM_DATA(journal_item)	((void *)(((everything_server_journal_item_t *)(journal_item)) + 1))

#define EVERYTHING_SERVER_PROV_RSA_AES            		24
#define EVERYTHING_SERVER_CRYPT_VERIFYCONTEXT     		0xF0000000
#define EVERYTHING_SERVER_ALG_CLASS_HASH				(4 << 13)
#define EVERYTHING_SERVER_ALG_TYPE_ANY              	(0)
#define EVERYTHING_SERVER_ALG_SID_SHA_256           	12
#define EVERYTHING_SERVER_CALG_SHA_256					(EVERYTHING_SERVER_ALG_CLASS_HASH | EVERYTHING_SERVER_ALG_TYPE_ANY | EVERYTHING_SERVER_ALG_SID_SHA_256)
#define EVERYTHING_SERVER_ALG_CLASS_DATA_ENCRYPT    	(3 << 13)
#define EVERYTHING_SERVER_ALG_TYPE_BLOCK            	(3 << 9)
#define EVERYTHING_SERVER_ALG_SID_AES_256				16
#define EVERYTHING_SERVER_CALG_AES_256            		(EVERYTHING_SERVER_ALG_CLASS_DATA_ENCRYPT|EVERYTHING_SERVER_ALG_TYPE_BLOCK|EVERYTHING_SERVER_ALG_SID_AES_256)

// AES 256 has a block size of 16.
#define EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE			16


//#define _EVERYTHING_SERVER_COMMAND_LOGIN				((DWORD)0) // <username-length> <username> <pasword-length> <password>
#define EVERYTHING_SERVER_COMMAND_ENUM_INDEX			((DWORD)1) 
#define EVERYTHING_SERVER_COMMAND_READ_JOURNAL			((DWORD)2) // <journal ID> <next item ID> (blocks until item id exists).
#define EVERYTHING_SERVER_COMMAND_LOGIN2				((DWORD)3) // <username-length> <username padded to 256 bytes>

#define EVERYTHING_SERVER_REPLY_SUCCESS					((DWORD)0)
#define EVERYTHING_SERVER_REPLY_SUCCESS_MORE_DATA		((DWORD)1) // keep recv'ing until EVERYTHING_SERVER_REPLY_SUCCESS
#define EVERYTHING_SERVER_REPLY_ERROR_JOURNAL_ENTRY_NOT_FOUND	((DWORD)2) // either the journal id changed or the item id has been deleted.

#define EVERYTHING_SERVER_PORT							14630 // INDEX
// 3506 // ESDB
// 0xe5db

#define EVERYTHING_SERVER_DEBUG_FATAL(...) everything_plugin_debug_fatal2((const everything_plugin_utf8_t *)__FILE__,__LINE__,(const everything_plugin_utf8_t *)__FUNCTION__,__VA_ARGS__)


// plugin ids
enum
{
	EVERYTHING_SERVER_PLUGIN_ID_ENABLED_CHECKBOX = 1000,
	EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_EDIT,
	EVERYTHING_SERVER_PLUGIN_ID_PORT_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_PORT_EDIT,
	EVERYTHING_SERVER_PLUGIN_ID_USER_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,
	EVERYTHING_SERVER_PLUGIN_ID_USER_ADD_BUTTON,
	EVERYTHING_SERVER_PLUGIN_ID_USER_REMOVE_BUTTON,
	EVERYTHING_SERVER_PLUGIN_ID_GROUP,
	EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,
	EVERYTHING_SERVER_PLUGIN_ID_REMAP_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,
	EVERYTHING_SERVER_PLUGIN_ID_REMAP_ADD_BUTTON,
	EVERYTHING_SERVER_PLUGIN_ID_REMAP_EDIT_BUTTON,
	EVERYTHING_SERVER_PLUGIN_ID_REMAP_REMOVE_BUTTON,
	EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_EDIT,
	EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT,
	EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_EDIT,
	_EVERYTHING_SERVER_PLUGIN_ID_LICENSE1,
	_EVERYTHING_SERVER_PLUGIN_ID_LICENSE2,
	_EVERYTHING_SERVER_PLUGIN_ID_LICENSE3,
	EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_STATIC,
	EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_STATIC,
};

#pragma pack (push,1)

// client data
typedef struct everything_server_msg_header_s
{
	// size includes header.
	DWORD size;
	DWORD command;
	
}everything_server_msg_header_t;

typedef struct everything_server_journal_data_s
{
    EVERYTHING_PLUGIN_QWORD remap_id;
    EVERYTHING_PLUGIN_QWORD journal_id;
    EVERYTHING_PLUGIN_QWORD item_index;
	
}everything_server_journal_data_t;

#pragma pack (pop)

// client data
typedef struct everything_server_index_snapshot_s
{
	everything_plugin_interlocked_t ref_count;

	// the snapshot.
	everything_plugin_db_snapshot_t *db_snapshot;

}everything_server_index_snapshot_t;

typedef struct everything_server_remap_s
{
	struct everything_server_remap_s *next;
	struct everything_server_remap_s *prev;
	
	everything_plugin_utf8_t *path;
	everything_plugin_utf8_t *mount;
	
}everything_server_remap_t;

typedef struct everything_server_remap_list_s
{
	struct everything_server_remap_s *start;
	struct everything_server_remap_s *last;
		
}everything_server_remap_list_t;

typedef struct everything_server_user_s
{
	struct everything_server_user_s *next;
	struct everything_server_user_s *prev;
	
	uintptr_t name_len;
	uintptr_t password_len;
	
	// index_snapshot can only be manipulated inside client_update
	// only used when timer is non-null
	// can only change in main thread.
	everything_server_index_snapshot_t *index_snapshot;

	// expire timer.
	everything_plugin_timer_t *index_snapshot_expire_timer;
	
	// an array of remappings.
	everything_plugin_db_remap_array_t *remap_array;
	EVERYTHING_PLUGIN_QWORD remap_id;
		
	everything_plugin_utf8_t *name;
	everything_plugin_utf8_t *password;
	everything_server_remap_list_t remap_list;
	
}everything_server_user_t;

typedef struct everything_server_user_list_s
{
	struct everything_server_user_s *start;
	struct everything_server_user_s *last;
		
}everything_server_user_list_t;

// client data
typedef struct everything_server_client_s
{
	everything_plugin_interlocked_t completion_routine_ref_count;
	
	struct everything_server_client_s *next;
	struct everything_server_client_s *prev;

	struct everything_server_client_s *send_event_next;
	struct everything_server_client_s *send_event_prev;

	struct everything_server_client_s *recv_event_next;
	struct everything_server_client_s *recv_event_prev;

	struct everything_server_client_s *index_request_next;
	struct everything_server_client_s *index_request_prev;

	struct everything_server_client_s *journal_request_next;
	struct everything_server_client_s *journal_request_prev;

	struct everything_server_client_s *journal_notification_next;
	struct everything_server_client_s *journal_notification_prev;

	// the user
	// NULL if not logged in.
	everything_server_user_t *user;

	EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET socket_handle;

	DWORD state;

	// recv	
	BYTE recv_stackbuf[EVERYTHING_SERVER_MAX_RECV_SIZE];
	BYTE *recv_p;
	DWORD recv_avail;
	EVERYTHING_PLUGIN_OS_WINSOCK_WSAOVERLAPPED recv_overlapped;
	
	// send
	BYTE send_stackbuf[EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE];
	everything_server_msg_header_t *send_buffer;
	BYTE *send_p;
	DWORD send_avail;
	EVERYTHING_PLUGIN_OS_WINSOCK_WSAOVERLAPPED send_overlapped;

	// index index_snapshot	
	// must be accessed inside cs.
	everything_server_index_snapshot_t *index_snapshot;
	everything_plugin_db_snapshot_file_t *index_snapshot_file;
	uintptr_t index_snapshot_avail;

	// journal index_snapshot
	// must be accessed inside cs.
	EVERYTHING_PLUGIN_QWORD journal_request_remap_id;
	EVERYTHING_PLUGIN_QWORD journal_request_journal_id;
	EVERYTHING_PLUGIN_QWORD journal_request_item_index;

	// data available in the current journal item.
	// will point inside journal_item_current.
	everything_plugin_db_journal_file_t *journal_file;

	int is_in_send_event_list;
	int is_in_recv_event_list;
	int is_in_index_request_list;
	
	int is_in_journal_request_list;
	int is_in_journal_notification_list;
	
	// encryption
	void *crypt_prov;
	
	// 0 if not logged in.
	void *crypt_encrypt_key;
	void *crypt_decrypt_key;
	
}everything_server_client_t;

// types
typedef struct everything_server_listen_s
{
	struct everything_server_listen_s *next;
	EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET listen_socket;
	EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT accept_event;

}everything_server_listen_t;

// types
typedef struct everything_server_wait_list_s
{
	HANDLE handles[EVERYTHING_PLUGIN_OS_WINSOCK_WSA_MAXIMUM_WAIT_EVENTS];
	DWORD count;
	int overflow;

}everything_server_wait_list_t;

// server data
typedef struct everything_server_s
{
	// list of listening sockets.
	everything_server_listen_t *listen_start;
	everything_server_listen_t *listen_last;

	// must be accessed in CS
	// list of clients.
	everything_server_client_t *client_start;
	everything_server_client_t *client_last;

	// must be accessed in CS
	// list of clients.
	everything_server_client_t *client_send_event_start;
	everything_server_client_t *client_send_event_last;

	// must be accessed in CS
	// list of clients.
	everything_server_client_t *client_recv_event_start;
	everything_server_client_t *client_recv_event_last;

	// list of clients waiting for a index_snapshot.
	everything_server_client_t *client_index_request_start;
	everything_server_client_t *client_index_request_last;

	// list of clients waiting for journal data.
	everything_server_client_t *client_journal_request_start;
	everything_server_client_t *client_journal_request_last;

	// list of clients waiting for journal notification.
	everything_server_client_t *client_journal_notification_start;
	everything_server_client_t *client_journal_notification_last;

	everything_plugin_os_thread_t *listen_thread;
	everything_plugin_os_thread_t *client_thread;
	
	// db ref.
	everything_plugin_db_t *db;
	
	// journal
	everything_plugin_db_journal_notification_t *journal_notification;
	
	everything_plugin_utf8_t *bindings;
	everything_server_user_list_t user_list;
	
	HANDLE listen_terminate_event;
	HANDLE client_terminate_event;
	EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT listen_wakeup_event;
	EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT client_wakeup_event;
	CRITICAL_SECTION cs;
	
	// a copy of the settings
	// so we can detect setting changes.
	int port;
	
	// crypt API
	HMODULE advapi32_hdll;
	BOOL (WINAPI *CryptCreateHash_proc)(void *hProv,unsigned int Algid,void *hKey,DWORD dwFlags,void **phHash);
	BOOL (WINAPI *CryptHashData_proc)(void *hHash,CONST BYTE *pbData,DWORD dwDataLen,DWORD dwFlags);
	BOOL (WINAPI *CryptDeriveKey_proc)(void *hProv,unsigned int Algid,void *hBaseData,DWORD dwFlags,void **phKey);
	BOOL (WINAPI *CryptDestroyHash_proc)(void *hHash);
	BOOL (WINAPI *CryptReleaseContext_proc)(void *hProv,DWORD dwFlags);
	BOOL (WINAPI *CryptDestroyKey_proc)(void *hKey);
	BOOL (WINAPI *CryptEncrypt_proc)(void *hKey,void *hHash,BOOL Final,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen,DWORD dwBufLen);
	BOOL (WINAPI *CryptDecrypt_proc)(void *hKey,void *hHash,BOOL Final,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen);
	void *crypt_prov;
	
}everything_server_t;

typedef struct everything_server_options_add_user_s
{
	struct everything_server_options_s *options;
	HWND options_hwnd;
	HWND page_hwnd;
	HWND hwnd;
	HWND tooltip_hwnd;
	struct everything_server_user_s *existing_user;
	
}everything_server_options_add_user_t;

typedef struct everything_server_options_add_remap_s
{
	struct everything_server_options_s *options;
	
	// the current selected user.
	struct everything_server_user_s *user;
	HWND options_hwnd;
	HWND page_hwnd;
	HWND hwnd;
	HWND tooltip_hwnd;
	struct everything_server_remap_s *existing_remap;
	
}everything_server_options_add_remap_t;

typedef struct everything_server_options_s
{
	// a list of users.
	everything_server_user_list_t user_list;
	
	int disallow_enable_apply;
		
}everything_server_options_t;

typedef struct everything_server_everything_plugin_proc_s
{
	const everything_plugin_utf8_t *name;
	void **proc_address_ptr;
	
}everything_server_everything_plugin_proc_t;

// client funcs
static everything_server_client_t *everything_server_client_create(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET socket_handle);
static void everything_server_client_destroy(everything_server_client_t *c);
static int everything_server_is_config_change(void);
static int everything_server_get_bind_addrinfo(const everything_plugin_utf8_t *nodename,struct everything_plugin_os_winsock_addrinfo **ai);
static DWORD WINAPI everything_server_listen_thread_proc(void *param);
static DWORD WINAPI everything_server_client_thread_proc(void *param);
static void everything_server_add_binding(const everything_plugin_utf8_t *nodename);
static void everything_server_wait_list_init(everything_server_wait_list_t *wait_list);
static void everything_server_wait_list_add(everything_server_wait_list_t *wait_list,HANDLE handle);
static int everything_server_client_do_recv(everything_server_client_t *c);
static void everything_server_client_add_send_event(everything_server_client_t *c);
static void everything_server_client_add_recv_event(everything_server_client_t *c);
static int everything_server_client_process_command(everything_server_client_t *c);
static int everything_server_client_process_login(everything_server_client_t *c);
static int everything_server_client_recv_data(everything_server_client_t *c,void *data,DWORD size);
static int everything_server_client_recv_next_command(everything_server_client_t *c);
static int everything_server_client_update_send(everything_server_client_t *c);
static int everything_server_client_update_recv(everything_server_client_t *c);
static int everything_server_client_send_msg(everything_server_client_t *c);
static void everything_server_client_setup_send_encrypt(everything_server_client_t *c,void *data,DWORD size);
static int everything_server_client_send_reply(everything_server_client_t *c,DWORD command);
static void CALLBACK everything_server_recv_completion_routine(DWORD dwError,DWORD cbTransferred,EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED lpOverlapped,DWORD dwFlags);
static void CALLBACK everything_server_send_completion_routine(DWORD dwError,DWORD cbTransferred,EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED lpOverlapped,DWORD dwFlags);
static void everything_server_client_request_index(everything_server_client_t *c);
static void WINAPI everything_server_request_index_event_proc(void *param);
static void everything_server_client_setup_send_first_index(everything_server_client_t *c);
static void everything_server_client_setup_send_next_index(everything_server_client_t *c);
static void everything_server_client_request_first_journal(everything_server_client_t *c,EVERYTHING_PLUGIN_QWORD remap_id,EVERYTHING_PLUGIN_QWORD journal_id,EVERYTHING_PLUGIN_QWORD item_index);
static void everything_server_client_request_next_journal(everything_server_client_t *c);
static void WINAPI everything_server_request_journal_event_proc(void *param);
static void WINAPI everything_server_journal_notification_callback_proc(void *param);
static void everything_server_index_snapshot_release(everything_server_index_snapshot_t *index_snapshot);
static void everything_server_index_snapshot_add_ref(everything_server_index_snapshot_t *index_snapshot);
static void EVERYTHING_PLUGIN_API everything_server_index_snapshot_expire_timer_proc(everything_server_user_t *user);
static void everything_server_client_free_send_buffer(everything_server_client_t *c);
static void everything_server_start(void);
static void everything_server_shutdown(void);
static int everything_server_apply_settings(void);
static void everything_server_update_options_page_user_list(HWND page_hwnd,everything_server_options_t *options,int select_index);
static void everything_server_update_options_page_remap_list(HWND page_hwnd,everything_server_options_t *options,everything_server_user_t *user,int select_index);
static void everything_server_update_options_page_buttons(HWND page_hwnd);
static void everything_server_create_options_checkbox(everything_plugin_load_options_page_t *load_options_page,int id,DWORD extra_style,const everything_plugin_utf8_t *text,const everything_plugin_utf8_t *tooltip,int checked);
static void everything_server_create_options_static(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *text);
static void everything_server_create_options_edit(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *tooltip,const everything_plugin_utf8_t *text);
static void everything_server_create_options_number_edit(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *tooltip,int value);
static void everything_server_create_options_password_edit(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *tooltip,const everything_plugin_utf8_t *text);
static void everything_server_create_options_button(everything_plugin_load_options_page_t *load_options_page,int id,DWORD extra_style,const everything_plugin_utf8_t *text,const everything_plugin_utf8_t *tooltip);
static void everything_server_enable_options_apply(HWND options_hwnd,everything_server_options_t *options);
static int everything_server_expand_min_wide(HWND page_hwnd,const everything_plugin_utf8_t *text,int current_wide);
static everything_plugin_utf8_t *everything_server_get_options_text(HWND page_hwnd,int id,everything_plugin_utf8_t *old_value);
static everything_server_user_t *everything_server_user_from_index(HWND page_hwnd,int index);
static everything_server_remap_t *everything_server_remap_from_index(HWND page_hwnd,int index);
static INT_PTR __stdcall everything_server_options_add_user_dialog_proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam);
static void everything_server_show_options_add_user_dialog(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options,everything_server_user_t *existing_user);
static void everything_server_user_free(everything_server_user_t *user);
static void everything_server_remap_free(everything_server_remap_t *remap);
static everything_server_user_t *everything_server_get_selected_user(HWND page_hwnd);
static everything_server_remap_t *everything_server_get_selected_remap(HWND page_hwnd);
static void everything_server_remove_selected_user(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options);
static void everything_server_remove_selected_remap(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options);
static void everything_server_edit_selected_user(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options);
static void everything_server_edit_selected_remap(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options);
static void everything_server_user_selection_changed(HWND page_hwnd,everything_server_options_t *options);
static void everything_server_remap_selection_changed(HWND page_hwnd,everything_server_options_t *options);
static void everything_server_user_setting_changed(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options);
static void everything_server_update_options_add_remap_buttons(HWND hwnd);
static INT_PTR __stdcall everything_server_options_add_remap_dialog_proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam);
static void everything_server_show_options_add_remap_dialog(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options,everything_server_remap_t *existing_remap);
static int everything_server_user_list_add(everything_server_user_list_t *user_list,const everything_plugin_utf8_t *name,uintptr_t name_len,const everything_plugin_utf8_t *password,uintptr_t password_len,const everything_plugin_utf8_t *include_only_path_list,const everything_plugin_utf8_t *include_only_mount_list,int replace);
static void everything_server_user_list_remove(everything_server_user_list_t *user_list,everything_server_user_t *user);
static void everything_server_user_list_init(everything_server_user_list_t *user_list);
static void everything_server_user_list_kill(everything_server_user_list_t *user_list);
static void everything_server_user_list_empty(everything_server_user_list_t *user_list);
static void everything_server_user_list_copy(everything_server_user_list_t *dst,const everything_server_user_list_t *src);
static void everything_server_user_list_load(everything_server_user_list_t *user_list,const everything_plugin_utf8_t *name_list,const everything_plugin_utf8_t *password_list,const everything_plugin_utf8_t *include_only_path_list,const everything_plugin_utf8_t *include_only_mount_list);
static int everything_server_remap_list_add(everything_server_remap_list_t *remap_list,const everything_plugin_utf8_t *path,const everything_plugin_utf8_t *mount,int replace);
static void everything_server_remap_list_remove(everything_server_remap_list_t *remap_list,everything_server_remap_t *remap);
static void everything_server_remap_list_init(everything_server_remap_list_t *remap_list);
static void everything_server_remap_list_kill(everything_server_remap_list_t *remap_list);
static void everything_server_remap_list_copy(everything_server_remap_list_t *dst,const everything_server_remap_list_t *src);
static void everything_server_remap_list_empty(everything_server_remap_list_t *remap_list);
static void everything_server_remap_list_load(everything_server_remap_list_t *remap_list,const everything_plugin_utf8_t *path_list,const everything_plugin_utf8_t *mount_list);
static void everything_server_remap_list_get_path_list(everything_server_remap_list_t *remap_list,everything_plugin_utf8_buf_t *cbuf);
static void everything_server_remap_list_get_mount_list(everything_server_remap_list_t *remap_list,everything_plugin_utf8_buf_t *cbuf);
static int everything_server_user_list_is_equal(const everything_server_user_list_t *a,const everything_server_user_list_t *b);
static int everything_server_is_all_nuls(const BYTE *data,uintptr_t len);

// static vars
static everything_server_t *_everything_server = 0;
int everything_server_enabled = 0;
int everything_server_port = EVERYTHING_SERVER_PORT;
everything_plugin_utf8_t *everything_server_bindings = 0;
everything_server_user_list_t everything_server_user_list;

static void *(EVERYTHING_PLUGIN_API *everything_plugin_mem_alloc)(uintptr_t size);
static void *(EVERYTHING_PLUGIN_API *everything_plugin_mem_calloc)(uintptr_t size);
static void (EVERYTHING_PLUGIN_API *everything_plugin_mem_free)(void *ptr);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_thread_wait_and_close)(everything_plugin_os_thread_t *t);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_closesocket)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_init)(everything_plugin_utf8_buf_t *cbuf);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_kill)(everything_plugin_utf8_buf_t *cbuf);
static const everything_plugin_utf8_t *(EVERYTHING_PLUGIN_API *everything_plugin_localization_get_string)(int id);
static everything_plugin_utf8_t *(EVERYTHING_PLUGIN_API *everything_plugin_get_setting_string)(struct sorted_list_s *sorted_list,const everything_plugin_utf8_t *name,everything_plugin_utf8_t *current_string);
static int (EVERYTHING_PLUGIN_API *everything_plugin_get_setting_int)(struct sorted_list_s *sorted_list,const everything_plugin_utf8_t *name,int current_value);
static void (EVERYTHING_PLUGIN_API *everything_plugin_debug_printf)(const everything_plugin_utf8_t *format,...);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_printf)(everything_plugin_utf8_buf_t *cbuf,const everything_plugin_utf8_t *format,...);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_empty)(everything_plugin_utf8_buf_t *cbuf);
static HANDLE (EVERYTHING_PLUGIN_API *everything_plugin_os_event_create)(void);
static everything_plugin_os_thread_t *(EVERYTHING_PLUGIN_API *everything_plugin_os_thread_create)(DWORD (EVERYTHING_PLUGIN_API *thread_proc)(void *),void *param);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_copy_memory)(void *dst,const void *src,uintptr_t size);
static everything_plugin_utf8_t *(EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_realloc_utf8_string)(everything_plugin_utf8_t *ptr,const everything_plugin_utf8_t *s);
static int (EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_compare)(const everything_plugin_utf8_t *start1,const everything_plugin_utf8_t *start2);
static void (EVERYTHING_PLUGIN_API *everything_plugin_debug_color_printf)(DWORD color,const everything_plugin_utf8_t *format,...);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_zero_memory)(void *ptr,uintptr_t size);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_getaddrinfo)(const char *nodename,const char *servname,const struct everything_plugin_os_winsock_addrinfo* hints,struct everything_plugin_os_winsock_addrinfo** res);
static EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_socket)(int af,int type,int protocol);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_bind)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,const struct everything_plugin_os_winsock_sockaddr *name,int namelen);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_listen)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,int backlog);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSAGetLastError)(void);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_freeaddrinfo)(struct everything_plugin_os_winsock_addrinfo* ai);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSAStartup)(WORD wVersionRequested,EVERYTHING_PLUGIN_OS_WINSOCK_WSADATA *lpWSAData);
static everything_plugin_utf8_t *(EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_alloc_utf8_string_n)(const everything_plugin_utf8_t *s,uintptr_t slen);
static everything_plugin_utf8_t *(EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_alloc_utf8_string)(const everything_plugin_utf8_t *s);
static everything_plugin_db_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_add_local_ref)(void);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_release)(everything_plugin_db_t *db);
static int (EVERYTHING_PLUGIN_API *everything_plugin_ui_task_dialog_show)(HWND parent_hwnd,UINT flags,const everything_plugin_utf8_t *caption,const everything_plugin_utf8_t *main_task,const everything_plugin_utf8_t *format,...);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSACleanup)(void);
static EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_accept)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,struct everything_plugin_os_sockaddr *addr,int *addrlen);
static void (EVERYTHING_PLUGIN_API *everything_plugin_network_set_tcp_nodelay)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET socket_handle);
static void (EVERYTHING_PLUGIN_API *everything_plugin_network_set_keepalive)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET socket_handle);
static uintptr_t (EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_get_length_in_bytes)(const everything_plugin_utf8_t *string);
static struct everything_plugin_ui_options_page_s *(EVERYTHING_PLUGIN_API *everything_plugin_ui_options_add_plugin_page)(struct everything_plugin_ui_options_add_custom_page_s *add_custom_page,void *user_data,const everything_plugin_utf8_t *name);
static void (EVERYTHING_PLUGIN_API *everything_plugin_set_setting_int)(struct everything_plugin_output_stream_s *output_stream,const everything_plugin_utf8_t *name,int value);
static void (EVERYTHING_PLUGIN_API *everything_plugin_set_setting_string)(everything_plugin_output_stream_t *output_stream,const everything_plugin_utf8_t *name,const everything_plugin_utf8_t *value);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_get_logical_wide)(void);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_get_logical_high)(void);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_set_dlg_rect)(HWND parent_hwnd,int id,int x,int y,int wide,int high);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_set_dlg_text)(HWND hDlg,int nIDDlgItem,const everything_plugin_utf8_t *s);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_get_dlg_text)(HWND hwnd,int id,everything_plugin_utf8_buf_t *cbuf);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_enable_or_disable_dlg_item)(HWND parent_hwnd,int id,int enable);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_checkbox)(HWND parent,int id,DWORD extra_style,int checked,const everything_plugin_utf8_t *text);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_add_tooltip)(HWND tooltip,HWND parent,int id,const everything_plugin_utf8_t *text);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_static)(HWND parent,int id,DWORD extra_window_style,const everything_plugin_utf8_t *text);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_edit)(HWND parent,int id,DWORD extra_style,const everything_plugin_utf8_t *text);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_number_edit)(HWND parent,int id,DWORD extra_style,__int64 number);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_password_edit)(HWND parent,int id,DWORD extra_style,const everything_plugin_utf8_t *text);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_button)(HWND parent,int id,DWORD extra_window_style,const everything_plugin_utf8_t *text);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_expand_dialog_text_logical_wide_no_prefix)(HWND parent,const everything_plugin_utf8_t *text,int wide);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_listbox)(HWND parent,int id,DWORD extra_style);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_group_box)(HWND parent,int id,const everything_plugin_utf8_t *text);
static int (EVERYTHING_PLUGIN_API *everything_plugin_config_get_int_value)(const everything_plugin_utf8_t *name);
static int (EVERYTHING_PLUGIN_API *everything_plugin_config_set_int_value)(const everything_plugin_utf8_t *name,int int_value);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_cat_utf8_string)(everything_plugin_utf8_buf_t *cbuf,const everything_plugin_utf8_t *s);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_cat_c_list_utf8_string)(everything_plugin_utf8_buf_t *cbuf,const everything_plugin_utf8_t *s);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_open_url)(const everything_plugin_utf8_t *url);
static HMODULE (EVERYTHING_PLUGIN_API *everything_plugin_os_load_system_library)(const everything_plugin_utf8_t *filename);
static EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSACreateEvent)(void);
static everything_plugin_db_remap_list_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_remap_list_create)(void);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_remap_list_destroy)(everything_plugin_db_remap_list_t *remap_list);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_remap_list_add)(everything_plugin_db_remap_list_t *remap_list,const everything_plugin_utf8_t *path,uintptr_t path_len,const everything_plugin_utf8_t *mount,uintptr_t mount_len);
static everything_plugin_db_remap_array_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_remap_array_create)(everything_plugin_db_remap_list_t *remap_list);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_remap_array_destroy)(everything_plugin_db_remap_array_t *remap_array);
static EVERYTHING_PLUGIN_QWORD (EVERYTHING_PLUGIN_API *everything_plugin_db_remap_array_get_hashcode)(const everything_plugin_db_remap_array_t *remap_array);
static everything_plugin_db_journal_notification_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_journal_notification_register)(everything_plugin_db_t *db,void *user_data,void (EVERYTHING_PLUGIN_API *callback)(void *user_data));
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_journal_notification_unregister)(everything_plugin_db_journal_notification_t *journal_notification);
static const everything_plugin_utf8_t *(EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_parse_c_item)(const everything_plugin_utf8_t *s,everything_plugin_utf8_buf_t *cbuf);
static BOOL (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSACloseEvent)(EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT hEvent);
static void (EVERYTHING_PLUGIN_API *everything_plugin_debug_error_printf)(const everything_plugin_utf8_t *format,...);
static BOOL (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSASetEvent)(EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT hEvent);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_thread_cancel_synchronous_io)(everything_plugin_os_thread_t *thread);
static void (EVERYTHING_PLUGIN_API *everything_plugin_event_post)(void (EVERYTHING_PLUGIN_API *proc)(void *user_data),void *user_data);
static void (EVERYTHING_PLUGIN_API *everything_plugin_event_remove)(void (EVERYTHING_PLUGIN_API *proc)(void *user_data),void *user_data);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_onready_add)(everything_plugin_db_t *db,void (EVERYTHING_PLUGIN_API *callback_proc)(void *user_data),void *user_data);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_onready_remove)(everything_plugin_db_t *db,void (EVERYTHING_PLUGIN_API *callback_proc)(void *user_data),void *user_data);
static uintptr_t (EVERYTHING_PLUGIN_API *everything_plugin_interlocked_inc)(everything_plugin_interlocked_t *interlocked);
static uintptr_t (EVERYTHING_PLUGIN_API *everything_plugin_interlocked_dec)(everything_plugin_interlocked_t *interlocked);
static void (EVERYTHING_PLUGIN_API *everything_plugin_interlocked_set)(everything_plugin_interlocked_t *interlocked,uintptr_t value);
static uintptr_t (EVERYTHING_PLUGIN_API *everything_plugin_interlocked_get)(everything_plugin_interlocked_t *interlocked);
static BOOL (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSAResetEvent)(EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT hEvent);
static DWORD (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSAWaitForMultipleEvents)(DWORD cEvents,const EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT *lphEvents,BOOL fWaitAll,DWORD dwTimeout,BOOL fAlertable);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_journal_file_close)(everything_plugin_db_journal_file_t *journal_file);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSAEventSelect)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT hEventObject,long lNetworkEvents);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSARecv)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,EVERYTHING_PLUGIN_OS_WINSOCK_WSABUF *lpBuffers,DWORD dwBufferCount,LPDWORD lpNumberOfBytesRecvd,DWORD *lpFlags,EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED lpOverlapped,EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_event_is_set)(HANDLE h);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSAEnumNetworkEvents)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT hEventObject,EVERYTHING_PLUGIN_OS_WINSOCK_WSANETWORKEVENTS *lpNetworkEvents);
static int (EVERYTHING_PLUGIN_API *everything_plugin_network_set_nonblocking)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET socket_handle);
static int (EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_compare_nocase_n_n)(const everything_plugin_utf8_t *s1start,uintptr_t s1startlen,const everything_plugin_utf8_t *s2start,uintptr_t s2startlen);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_winsock_WSASend)(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET s,EVERYTHING_PLUGIN_OS_WINSOCK_WSABUF *lpBuffers,DWORD dwBufferCount,DWORD *lpNumberOfBytesSent,DWORD dwFlags,EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED lpOverlapped,EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine);
static void (EVERYTHING_PLUGIN_API *everything_plugin_debug_fatal2)(const everything_plugin_utf8_t *file,int line,const everything_plugin_utf8_t *function,const everything_plugin_utf8_t *format,...);
static int (EVERYTHING_PLUGIN_API *everything_plugin_db_would_block)(everything_plugin_db_t *db);
static int (EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_is_out_of_date)(const everything_plugin_db_snapshot_t *snapshot,everything_plugin_db_t *db,const everything_plugin_db_remap_array_t *remap_array);
static everything_plugin_timer_t *(EVERYTHING_PLUGIN_API *everything_plugin_timer_create)(void (EVERYTHING_PLUGIN_API *callback_proc)(void *user_data),void *user_data,DWORD elapsed_milliseconds);
static void (EVERYTHING_PLUGIN_API *everything_plugin_timer_destroy)(everything_plugin_timer_t *timer);
static everything_plugin_db_snapshot_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_create)(everything_plugin_db_t *db,const everything_plugin_db_remap_array_t *remap_array);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_destroy)(everything_plugin_db_snapshot_t *snapshot);
static uintptr_t (EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_get_size)(everything_plugin_db_snapshot_t *snapshot);
static everything_plugin_db_snapshot_file_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_file_open)(everything_plugin_db_snapshot_t *snapshot);
static void (EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_file_close)(everything_plugin_db_snapshot_file_t *snapshot_file);
static uintptr_t (EVERYTHING_PLUGIN_API *everything_plugin_db_snapshot_file_read)(everything_plugin_db_snapshot_file_t *snapshot_file,void *buf,uintptr_t len);
static everything_plugin_db_journal_file_t *(EVERYTHING_PLUGIN_API *everything_plugin_db_journal_file_open)(everything_plugin_db_t *db,const everything_plugin_db_remap_array_t *remap_array,EVERYTHING_PLUGIN_QWORD journal_id,EVERYTHING_PLUGIN_QWORD first_item_index);
static int (EVERYTHING_PLUGIN_API *everything_plugin_db_journal_file_would_block)(everything_plugin_db_journal_file_t *journal_file);
static int (EVERYTHING_PLUGIN_API *everything_plugin_db_journal_file_read)(everything_plugin_db_journal_file_t *journal_file,void *buf,uintptr_t len,uintptr_t *pnumread);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_set_dlg_redraw)(HWND hwnd,int id,BOOL redraw);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_clear_listbox)(HWND hwnd,int id);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_add_listbox_string_and_data)(HWND hwnd,int id,const everything_plugin_utf8_t *s,const void *data);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_set_listbox_cur_sel)(HWND hwnd,int id,int index);
static int (EVERYTHING_PLUGIN_API *everything_plugin_os_get_listbox_cur_sel)(HWND hwnd,int id);
static void *(EVERYTHING_PLUGIN_API *everything_plugin_os_get_listbox_data)(HWND hwnd,int id,int index);
static void *(EVERYTHING_PLUGIN_API *everything_plugin_os_get_window_user_data)(HWND hwnd);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_set_window_user_data)(HWND hwnd,void *user_data);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_center_dialog)(HWND parent_hwnd,HWND hwnd,int client_logical_wide,int client_logical_high);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_force_ltr_edit)(HWND hwnd,int id);
static void (EVERYTHING_PLUGIN_API *everything_plugin_os_set_default_button)(HWND hwnd,int id);
static HWND (EVERYTHING_PLUGIN_API *everything_plugin_os_create_tooltip)(void);
static void *(EVERYTHING_PLUGIN_API *everything_plugin_os_create_blank_dialog)(HWND parent_hwnd,const everything_plugin_utf8_t *class_name,const everything_plugin_utf8_t *title,int resizable,int modeless,DWORD extra_ex_style,DWORD extra_style,DLGPROC proc,void *param);
static int (EVERYTHING_PLUGIN_API *everything_plugin_utf8_string_icompare)(const everything_plugin_utf8_t *s1start,const everything_plugin_utf8_t *s2start);
static void (EVERYTHING_PLUGIN_API *everything_plugin_utf8_buf_copy_utf8_string_n)(everything_plugin_utf8_buf_t *cbuf,const everything_plugin_utf8_t *s,uintptr_t slen);

// required procs supplied from Everything.
static everything_server_everything_plugin_proc_t everything_server_everything_plugin_proc_array[] =
{
 	{"mem_alloc",(void *)&everything_plugin_mem_alloc},
 	{"mem_calloc",(void *)&everything_plugin_mem_calloc},
 	{"mem_free",(void *)&everything_plugin_mem_free},
 	{"os_thread_wait_and_close",(void *)&everything_plugin_os_thread_wait_and_close},
 	{"os_winsock_closesocket",(void *)&everything_plugin_os_winsock_closesocket},
 	{"utf8_buf_init",(void *)&everything_plugin_utf8_buf_init},
 	{"utf8_buf_kill",(void *)&everything_plugin_utf8_buf_kill},
 	{"localization_get_string",(void *)&everything_plugin_localization_get_string},
 	{"plugin_get_setting_string",(void *)&everything_plugin_get_setting_string},
	{"plugin_get_setting_int",(void *)&everything_plugin_get_setting_int},
 	{"debug_printf",(void *)&everything_plugin_debug_printf},
 	{"utf8_buf_printf",(void *)&everything_plugin_utf8_buf_printf},
 	{"utf8_buf_empty",(void *)&everything_plugin_utf8_buf_empty},
 	{"os_event_create",(void *)&everything_plugin_os_event_create},
 	{"os_thread_create",(void *)&everything_plugin_os_thread_create},
 	{"os_copy_memory",(void *)&everything_plugin_os_copy_memory},
 	{"utf8_string_realloc_utf8_string",(void *)&everything_plugin_utf8_string_realloc_utf8_string},
 	{"utf8_string_compare",(void *)&everything_plugin_utf8_string_compare},
 	{"debug_color_printf",(void *)&everything_plugin_debug_color_printf},
 	{"os_zero_memory",(void *)&everything_plugin_os_zero_memory},
 	{"os_winsock_getaddrinfo",(void *)&everything_plugin_os_winsock_getaddrinfo},
 	{"os_winsock_socket",(void *)&everything_plugin_os_winsock_socket},
 	{"os_winsock_bind",(void *)&everything_plugin_os_winsock_bind},
 	{"os_winsock_listen",(void *)&everything_plugin_os_winsock_listen},
 	{"os_winsock_WSAGetLastError",(void *)&everything_plugin_os_winsock_WSAGetLastError},
 	{"os_winsock_freeaddrinfo",(void *)&everything_plugin_os_winsock_freeaddrinfo},
 	{"os_winsock_WSAStartup",(void *)&everything_plugin_os_winsock_WSAStartup},
 	{"os_winsock_WSACleanup",(void *)&everything_plugin_os_winsock_WSACleanup},
 	{"utf8_string_alloc_utf8_string_n",(void *)&everything_plugin_utf8_string_alloc_utf8_string_n},
 	{"utf8_string_alloc_utf8_string",(void *)&everything_plugin_utf8_string_alloc_utf8_string},
 	{"db_add_local_ref",(void *)&everything_plugin_db_add_local_ref},
 	{"db_release",(void *)&everything_plugin_db_release},
 	{"ui_task_dialog_show",(void *)&everything_plugin_ui_task_dialog_show},
 	{"os_winsock_accept",(void *)&everything_plugin_os_winsock_accept},
 	{"network_set_tcp_nodelay",(void *)&everything_plugin_network_set_tcp_nodelay},
 	{"network_set_keepalive",(void *)&everything_plugin_network_set_keepalive},
	{"utf8_string_get_length_in_bytes",(void *)&everything_plugin_utf8_string_get_length_in_bytes},
	{"ui_options_add_plugin_page",(void *)&everything_plugin_ui_options_add_plugin_page},
 	{"plugin_set_setting_int",(void *)&everything_plugin_set_setting_int},
 	{"plugin_set_setting_string",(void *)&everything_plugin_set_setting_string},
 	{"os_get_logical_wide",(void *)&everything_plugin_os_get_logical_wide},
 	{"os_get_logical_high",(void *)&everything_plugin_os_get_logical_high},
 	{"os_set_dlg_rect",(void *)&everything_plugin_os_set_dlg_rect},
 	{"os_set_dlg_text",(void *)&everything_plugin_os_set_dlg_text},
 	{"os_get_dlg_text",(void *)&everything_plugin_os_get_dlg_text},
 	{"os_enable_or_disable_dlg_item",(void *)&everything_plugin_os_enable_or_disable_dlg_item},
 	{"os_create_checkbox",(void *)&everything_plugin_os_create_checkbox},
 	{"os_add_tooltip",(void *)&everything_plugin_os_add_tooltip},
 	{"os_create_static",(void *)&everything_plugin_os_create_static},
 	{"os_create_edit",(void *)&everything_plugin_os_create_edit},
 	{"os_create_number_edit",(void *)&everything_plugin_os_create_number_edit},
 	{"os_create_password_edit",(void *)&everything_plugin_os_create_password_edit},
 	{"os_create_button",(void *)&everything_plugin_os_create_button},
 	{"os_expand_dialog_text_logical_wide_no_prefix",(void *)&everything_plugin_os_expand_dialog_text_logical_wide_no_prefix},
 	{"os_create_listbox",(void *)&everything_plugin_os_create_listbox},
 	{"os_create_group_box",(void *)&everything_plugin_os_create_group_box},
 	{"config_get_int_value",(void *)&everything_plugin_config_get_int_value},
 	{"config_set_int_value",(void *)&everything_plugin_config_set_int_value},
 	{"utf8_buf_cat_utf8_string",(void *)&everything_plugin_utf8_buf_cat_utf8_string},
 	{"utf8_buf_cat_c_list_utf8_string",(void *)&everything_plugin_utf8_buf_cat_c_list_utf8_string},
 	{"os_open_url",(void *)&everything_plugin_os_open_url},
 	{"os_load_system_library",(void *)&everything_plugin_os_load_system_library},
 	{"os_winsock_WSACreateEvent",(void *)&everything_plugin_os_winsock_WSACreateEvent},
 	{"db_remap_list_create",(void *)&everything_plugin_db_remap_list_create},
 	{"db_remap_list_destroy",(void *)&everything_plugin_db_remap_list_destroy},
 	{"db_remap_list_add",(void *)&everything_plugin_db_remap_list_add},
 	{"db_remap_array_create",(void *)&everything_plugin_db_remap_array_create},
 	{"db_remap_array_destroy",(void *)&everything_plugin_db_remap_array_destroy},
 	{"db_remap_array_get_hashcode",(void *)&everything_plugin_db_remap_array_get_hashcode},
 	{"db_journal_notification_register",(void *)&everything_plugin_db_journal_notification_register},
 	{"db_journal_notification_unregister",(void *)&everything_plugin_db_journal_notification_unregister},
 	{"utf8_string_parse_c_item",(void *)&everything_plugin_utf8_string_parse_c_item},
 	{"os_winsock_WSACloseEvent",(void *)&everything_plugin_os_winsock_WSACloseEvent},
 	{"debug_error_printf",(void *)&everything_plugin_debug_error_printf},
 	{"os_winsock_WSASetEvent",(void *)&everything_plugin_os_winsock_WSASetEvent},
 	{"os_thread_cancel_synchronous_io",(void *)&everything_plugin_os_thread_cancel_synchronous_io},
 	{"event_post",(void *)&everything_plugin_event_post},
 	{"event_remove",(void *)&everything_plugin_event_remove},
 	{"db_onready_add",(void *)&everything_plugin_db_onready_add},
 	{"db_onready_remove",(void *)&everything_plugin_db_onready_remove},
 	{"interlocked_inc",(void *)&everything_plugin_interlocked_inc},
 	{"interlocked_dec",(void *)&everything_plugin_interlocked_dec},
 	{"interlocked_set",(void *)&everything_plugin_interlocked_set},
 	{"interlocked_get",(void *)&everything_plugin_interlocked_get},
 	{"os_winsock_WSAResetEvent",(void *)&everything_plugin_os_winsock_WSAResetEvent},
 	{"os_winsock_WSAWaitForMultipleEvents",(void *)&everything_plugin_os_winsock_WSAWaitForMultipleEvents},
 	{"db_journal_file_close",(void *)&everything_plugin_db_journal_file_close},
 	{"os_winsock_WSAEventSelect",(void *)&everything_plugin_os_winsock_WSAEventSelect},
 	{"os_winsock_WSARecv",(void *)&everything_plugin_os_winsock_WSARecv},
 	{"os_event_is_set",(void *)&everything_plugin_os_event_is_set},
 	{"os_winsock_WSAEnumNetworkEvents",(void *)&everything_plugin_os_winsock_WSAEnumNetworkEvents},
 	{"network_set_nonblocking",(void *)&everything_plugin_network_set_nonblocking},
 	{"utf8_string_compare_nocase_n_n",(void *)&everything_plugin_utf8_string_compare_nocase_n_n},
 	{"os_winsock_WSASend",(void *)&everything_plugin_os_winsock_WSASend},
 	{"debug_fatal2",(void *)&everything_plugin_debug_fatal2},
 	{"db_would_block",(void *)&everything_plugin_db_would_block},
 	{"db_snapshot_is_out_of_date",(void *)&everything_plugin_db_snapshot_is_out_of_date},
 	{"timer_create",(void *)&everything_plugin_timer_create},
 	{"timer_destroy",(void *)&everything_plugin_timer_destroy},
 	{"db_snapshot_create",(void *)&everything_plugin_db_snapshot_create},
 	{"db_snapshot_destroy",(void *)&everything_plugin_db_snapshot_destroy},
 	{"db_snapshot_get_size",(void *)&everything_plugin_db_snapshot_get_size},
 	{"db_snapshot_file_open",(void *)&everything_plugin_db_snapshot_file_open},
 	{"db_snapshot_file_close",(void *)&everything_plugin_db_snapshot_file_close},
 	{"db_snapshot_file_read",(void *)&everything_plugin_db_snapshot_file_read},
 	{"db_journal_file_open",(void *)&everything_plugin_db_journal_file_open},
 	{"db_journal_file_would_block",(void *)&everything_plugin_db_journal_file_would_block},
 	{"db_journal_file_read",(void *)&everything_plugin_db_journal_file_read},
 	{"os_set_dlg_redraw",(void *)&everything_plugin_os_set_dlg_redraw},
 	{"os_clear_listbox",(void *)&everything_plugin_os_clear_listbox},
 	{"os_add_listbox_string_and_data",(void *)&everything_plugin_os_add_listbox_string_and_data},
 	{"os_set_listbox_cur_sel",(void *)&everything_plugin_os_set_listbox_cur_sel},
 	{"os_get_listbox_cur_sel",(void *)&everything_plugin_os_get_listbox_cur_sel},
 	{"os_get_listbox_data",(void *)&everything_plugin_os_get_listbox_data},
 	{"os_get_window_user_data",(void *)&everything_plugin_os_get_window_user_data},
 	{"os_set_window_user_data",(void *)&everything_plugin_os_set_window_user_data},
 	{"os_center_dialog",(void *)&everything_plugin_os_center_dialog},
 	{"os_force_ltr_edit",(void *)&everything_plugin_os_force_ltr_edit},
 	{"os_set_default_button",(void *)&everything_plugin_os_set_default_button},
 	{"os_create_tooltip",(void *)&everything_plugin_os_create_tooltip},
 	{"os_create_blank_dialog",(void *)&everything_plugin_os_create_blank_dialog},
 	{"utf8_string_icompare",(void *)&everything_plugin_utf8_string_icompare},
 	{"utf8_buf_copy_utf8_string_n",(void *)&everything_plugin_utf8_buf_copy_utf8_string_n},
};
	
#define EVERYTHING_SERVER_EVERYTHING_PLUGIN_PROC_COUNT (sizeof(everything_server_everything_plugin_proc_array) / sizeof(everything_server_everything_plugin_proc_t))

__declspec( dllexport) void * EVERYTHING_PLUGIN_API everything_plugin_proc(DWORD msg,void *data)
{
	switch(msg)
	{
		case EVERYTHING_PLUGIN_PM_INIT:
		
			// find procs.
			
			{
				uintptr_t index;
				
				for(index=0;index<EVERYTHING_SERVER_EVERYTHING_PLUGIN_PROC_COUNT;index++)
				{
					void *proc;
					
					proc = ((everything_plugin_get_proc_address_t)data)(everything_server_everything_plugin_proc_array[index].name);
					
					if (!proc)
					{
						return (void *)0;
					}
					
					*everything_server_everything_plugin_proc_array[index].proc_address_ptr = proc;
				}
			}
		
			everything_server_bindings = everything_plugin_utf8_string_alloc_utf8_string((const everything_plugin_utf8_t *)"");;
			
			everything_server_user_list_init(&everything_server_user_list);

			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_START:
		
			// load settings
			everything_server_enabled = everything_plugin_get_setting_int(data,(const everything_plugin_utf8_t *)"enabled",everything_server_enabled);
			everything_server_port = everything_plugin_get_setting_int(data,(const everything_plugin_utf8_t *)"port",everything_server_port);
			everything_server_bindings = everything_plugin_get_setting_string(data,(const everything_plugin_utf8_t *)"bindings",everything_server_bindings);

			// load users.
			{
				everything_plugin_utf8_t *user_list;
				everything_plugin_utf8_t *password_list;
				everything_plugin_utf8_t *include_only_path_list;
				everything_plugin_utf8_t *include_only_mount_list;
				
				user_list = everything_plugin_get_setting_string(data,(const everything_plugin_utf8_t *)"users",NULL);
				password_list = everything_plugin_get_setting_string(data,(const everything_plugin_utf8_t *)"password",NULL);
				include_only_path_list = everything_plugin_get_setting_string(data,(const everything_plugin_utf8_t *)"include_only_path",NULL);
				include_only_mount_list = everything_plugin_get_setting_string(data,(const everything_plugin_utf8_t *)"include_only_mount",NULL);
				
				everything_server_user_list_load(&everything_server_user_list,user_list,password_list,include_only_path_list,include_only_mount_list);

				if (include_only_mount_list)
				{
					everything_plugin_mem_free(include_only_mount_list);
				}
				
				if (include_only_path_list)
				{
					everything_plugin_mem_free(include_only_path_list);
				}
				
				if (password_list)
				{
					everything_plugin_mem_free(password_list);
				}
				
				if (user_list)
				{
					everything_plugin_mem_free(user_list);
				}
			}

			// apply settings.
			everything_server_apply_settings();
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_STOP:
			everything_server_shutdown();
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_KILL:

			everything_server_user_list_kill(&everything_server_user_list);
		
			everything_plugin_mem_free(everything_server_bindings);
			
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_GET_PLUGIN_VERSION:
			return (void *)EVERYTHING_PLUGIN_VERSION;
			
		case EVERYTHING_PLUGIN_PM_GET_NAME:
			return (void *)everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_EVERYTHING_SERVER);
			
		case EVERYTHING_PLUGIN_PM_GET_DESCRIPTION:
			return (void *)everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_EVERYTHING_SERVER_DESCRIPTION);
			
		case EVERYTHING_PLUGIN_PM_GET_AUTHOR:
			return "voidtools";
			
		case EVERYTHING_PLUGIN_PM_GET_VERSION:
			return PLUGINVERSION;
			
		case EVERYTHING_PLUGIN_PM_GET_LINK:
			return (void *)everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_PLUGIN_LINK);
				
		case EVERYTHING_PLUGIN_PM_ADD_OPTIONS_PAGES:
		
			{
				everything_server_options_t *options;
				
				options = everything_plugin_mem_alloc(sizeof(everything_server_options_t));
				
				options->disallow_enable_apply = 0;
				
				everything_server_user_list_init(&options->user_list);
				
				everything_plugin_ui_options_add_plugin_page(data,options,everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_EVERYTHING_SERVER));
			}
			
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_KILL_OPTIONS_PAGE:
		
			// free list.
			everything_server_user_list_kill(&((everything_server_options_t *)data)->user_list);
		
			everything_plugin_mem_free(data);
		
			return (void *)1;

		case EVERYTHING_PLUGIN_PM_LOAD_OPTIONS_PAGE:
		
			{
				everything_server_options_t *options;
				HWND page_hwnd;
				
				options = (everything_server_options_t *)((everything_plugin_save_options_page_t *)data)->user_data;
				page_hwnd = ((everything_plugin_load_options_page_t *)data)->page_hwnd;
				
				everything_server_user_list_copy(&options->user_list,&everything_server_user_list);

//DEBUG_FIXME("alpha ONLY enterprise info");

//				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_LICENSE1,"Running an Everything Server requires a site license.");
//				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_LICENSE2,"See voidtools.com/enterprise for more information.");
//				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_LICENSE3,"Alpha: Please make sure the Index Journal is enabled.");
				
				everything_server_create_options_checkbox(data,EVERYTHING_SERVER_PLUGIN_ID_ENABLED_CHECKBOX,WS_GROUP,"Enable Everything Server","Enable or disable the Everything Server",everything_server_enabled);
				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_STATIC,"Bind to &interfaces:");
				everything_server_create_options_edit(data,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_EDIT,"Listen for new connections on the specified semicolon delimited list of interfaces.\nEmpty = Listen on all interfaces.",everything_server_bindings);
				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_PORT_STATIC,"&Port:");
				everything_server_create_options_number_edit(data,EVERYTHING_SERVER_PLUGIN_ID_PORT_EDIT,"Everything server port number",everything_server_port);
				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_USER_STATIC,"&User Accounts:");

				everything_plugin_os_create_listbox(((everything_plugin_load_options_page_t *)data)->page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,WS_GROUP|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT|LBS_WANTKEYBOARDINPUT);
				everything_plugin_os_add_tooltip(((everything_plugin_load_options_page_t *)data)->tooltip_hwnd,((everything_plugin_load_options_page_t *)data)->page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,"A list of user accounts.\nClients are required to login with one of these user account credentials.");
				
				everything_server_create_options_button(data,EVERYTHING_SERVER_PLUGIN_ID_USER_ADD_BUTTON,WS_GROUP,"Add...","Create a new user account with specific file access.");
				everything_server_create_options_button(data,EVERYTHING_SERVER_PLUGIN_ID_USER_REMOVE_BUTTON,0,"Remove","Remove the selected user account.");
				
				everything_plugin_os_create_group_box(((everything_plugin_load_options_page_t *)data)->page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_GROUP,"Settings for selected user account");
				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_STATIC,"Password:");
				everything_server_create_options_password_edit(data,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,"Set the password for the selected user account.","");
				everything_server_create_options_static(data,EVERYTHING_SERVER_PLUGIN_ID_REMAP_STATIC,"Include only:");
				everything_plugin_os_create_listbox(((everything_plugin_load_options_page_t *)data)->page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,WS_GROUP|LBS_NOTIFY|LBS_NOINTEGRALHEIGHT|LBS_WANTKEYBOARDINPUT);
				everything_plugin_os_add_tooltip(((everything_plugin_load_options_page_t *)data)->tooltip_hwnd,((everything_plugin_load_options_page_t *)data)->page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,"A list of paths to include (and optionally remap)\nEmpty = include all.");
				everything_server_create_options_button(data,EVERYTHING_SERVER_PLUGIN_ID_REMAP_ADD_BUTTON,WS_GROUP,"Add...","Create a new include only and optional remapping.");
				everything_server_create_options_button(data,EVERYTHING_SERVER_PLUGIN_ID_REMAP_EDIT_BUTTON,0,"Edit...","Edit the selected include only.");
				everything_server_create_options_button(data,EVERYTHING_SERVER_PLUGIN_ID_REMAP_REMOVE_BUTTON,0,"Remove","Remove the selected include only.");

				everything_server_update_options_page_user_list(page_hwnd,((everything_plugin_load_options_page_t *)data)->user_data,0);
			}
			
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_SAVE_OPTIONS_PAGE:

			{
				int is_enabled;
				everything_server_options_t *options;
				HWND page_hwnd;
				
				options = (everything_server_options_t *)((everything_plugin_save_options_page_t *)data)->user_data;
				page_hwnd = ((everything_plugin_save_options_page_t *)data)->page_hwnd;
				
				is_enabled = (IsDlgButtonChecked(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_ENABLED_CHECKBOX) == BST_CHECKED);
				
				if ((!everything_server_enabled) && (is_enabled))
				{
/*
					if (_ui_options_require_journal())
					{
						is_enabled = 0;
						((everything_plugin_save_options_page_t *)data)->enable_apply = 1;
					}*/
					if (!everything_plugin_config_get_int_value("journal"))
					{
						int ret;
						
						ret = everything_plugin_ui_task_dialog_show(page_hwnd,MB_ICONQUESTION|MB_YESNOCANCEL,"Index Journal","Enable Index Journal?","The Index Journal is required to keep client indexes up to date.");
						if (ret == IDYES)
						{
							everything_plugin_config_set_int_value("journal",1);
						}
						else
						if (ret == IDCANCEL)
						{
							is_enabled = 0;
							((everything_plugin_save_options_page_t *)data)->enable_apply = 1;
						}
					}
				}
				
				if ((!everything_server_enabled) && (is_enabled))
				{
					if (everything_plugin_config_get_int_value("journal_max_size") < 32 * 1024 * 1024)
					{
						int ret;
						
						ret = everything_plugin_ui_task_dialog_show(page_hwnd,MB_ICONQUESTION|MB_YESNOCANCEL,"Index Journal","Increase Index Journal size to 32 MB?","An Index Journal size of at least 32 MB is recommended.");
						if (ret == IDYES)
						{
							everything_plugin_config_set_int_value("journal_max_size",32 * 1024 * 1024);
						}
						else
						if (ret == IDCANCEL)
						{
							is_enabled = 0;
							((everything_plugin_save_options_page_t *)data)->enable_apply = 1;
						}
					}
				}
				
				if ((!everything_server_enabled) && (is_enabled))
				{
					if ((everything_plugin_config_get_int_value("auto_include_fixed_ntfs_volumes")) || (everything_plugin_config_get_int_value("auto_include_removable_ntfs_volumes")) || (everything_plugin_config_get_int_value("auto_move_ntfs_volumes")) || (everything_plugin_config_get_int_value("auto_include_fixed_refs_volumes")) || (everything_plugin_config_get_int_value("auto_include_removable_refs_volumes"))|| (everything_plugin_config_get_int_value("auto_move_refs_volumes")) || (everything_plugin_config_get_int_value("auto_include_fixed_fat_volumes")) || (everything_plugin_config_get_int_value("auto_include_removable_fat_volumes"))|| (everything_plugin_config_get_int_value("auto_move_fat_volumes")) || (everything_plugin_config_get_int_value("auto_include_remote_volumes")))
					{
						int ret;
						
						ret = everything_plugin_ui_task_dialog_show(page_hwnd,MB_ICONQUESTION|MB_YESNOCANCEL,"Automatically Include New volumes","Disable Automatically include new volumes?","Clients may have undesired access to new volumes.");
						if (ret == IDYES)
						{
							everything_plugin_config_set_int_value("auto_include_fixed_ntfs_volumes",0);
							everything_plugin_config_set_int_value("auto_include_removable_ntfs_volumes",0);
							everything_plugin_config_set_int_value("auto_move_ntfs_volumes",0);
							everything_plugin_config_set_int_value("auto_include_fixed_refs_volumes",0);
							everything_plugin_config_set_int_value("auto_include_removable_refs_volumes",0);
							everything_plugin_config_set_int_value("auto_move_refs_volumes",0);
							everything_plugin_config_set_int_value("auto_include_fixed_fat_volumes",0);
							everything_plugin_config_set_int_value("auto_include_removable_fat_volumes",0);
							everything_plugin_config_set_int_value("auto_move_fat_volumes",0);
							everything_plugin_config_set_int_value("auto_include_remote_volumes",0);
						}
						else
						if (ret == IDNO)
						{
							// leave as is.
						}
						else
						if (ret == IDCANCEL)
						{
							is_enabled = 0;
							((everything_plugin_save_options_page_t *)data)->enable_apply = 1;
						}
					}
				}
				
				everything_server_enabled = is_enabled;
				everything_server_bindings = everything_server_get_options_text(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_EDIT,everything_server_bindings);
				everything_server_port = GetDlgItemInt(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PORT_EDIT,NULL,FALSE);
				everything_server_user_list_copy(&everything_server_user_list,&options->user_list);

				// restart servers?
				// why not ask the user..
				if (!everything_server_apply_settings())
				{
					((everything_plugin_save_options_page_t *)data)->enable_apply = 1;
				}
			}
			
			return (void *)1;

		case EVERYTHING_PLUGIN_PM_SAVE_SETTINGS:
					
			// save settings
			everything_plugin_set_setting_int(data,(const everything_plugin_utf8_t *)"enabled",everything_server_enabled);
			everything_plugin_set_setting_int(data,(const everything_plugin_utf8_t *)"port",everything_server_port);
			everything_plugin_set_setting_string(data,(const everything_plugin_utf8_t *)"bindings",everything_server_bindings);
			
			// save users.
			{
				everything_server_user_t *user;
				everything_plugin_utf8_buf_t value_cbuf;
				everything_plugin_utf8_buf_t remap_cbuf;
				
				everything_plugin_utf8_buf_init(&value_cbuf);
				everything_plugin_utf8_buf_init(&remap_cbuf);
				
				// name
				user = everything_server_user_list.start;
				
				while(user)
				{
					if (user != everything_server_user_list.start)
					{
						everything_plugin_utf8_buf_cat_utf8_string(&value_cbuf,";");
					}
					
					if (user->name_len)
					{
						everything_plugin_utf8_buf_cat_c_list_utf8_string(&value_cbuf,user->name);
					}
					else
					{
						everything_plugin_utf8_buf_cat_utf8_string(&value_cbuf,"\"\"");
					}
					
					user = user->next;
				}

				everything_plugin_set_setting_string(data,(const everything_plugin_utf8_t *)"users",value_cbuf.buf);

				// password
				user = everything_server_user_list.start;
				everything_plugin_utf8_buf_empty(&value_cbuf);
				
				while(user)
				{
					if (user != everything_server_user_list.start)
					{
						everything_plugin_utf8_buf_cat_utf8_string(&value_cbuf,";");
					}
					
					everything_plugin_utf8_buf_cat_c_list_utf8_string(&value_cbuf,user->password);
					
					user = user->next;
				}

				everything_plugin_set_setting_string(data,(const everything_plugin_utf8_t *)"password",value_cbuf.buf);

				// save remaps.
				user = everything_server_user_list.start;
				everything_plugin_utf8_buf_empty(&value_cbuf);
				
				while(user)
				{
					if (user != everything_server_user_list.start)
					{
						everything_plugin_utf8_buf_cat_utf8_string(&value_cbuf,";");
					}
					
					everything_server_remap_list_get_path_list(&user->remap_list,&remap_cbuf);
					
					everything_plugin_utf8_buf_cat_c_list_utf8_string(&value_cbuf,remap_cbuf.buf);
					
					user = user->next;
				}
				
				everything_plugin_set_setting_string(data,(const everything_plugin_utf8_t *)"include_only_path",value_cbuf.buf);

				// save remaps.
				user = everything_server_user_list.start;
				everything_plugin_utf8_buf_empty(&value_cbuf);
				
				while(user)
				{
					if (user != everything_server_user_list.start)
					{
						everything_plugin_utf8_buf_cat_utf8_string(&value_cbuf,";");
					}
					
					everything_server_remap_list_get_mount_list(&user->remap_list,&remap_cbuf);
					
					everything_plugin_utf8_buf_cat_c_list_utf8_string(&value_cbuf,remap_cbuf.buf);
					
					user = user->next;
				}
				
				everything_plugin_set_setting_string(data,(const everything_plugin_utf8_t *)"include_only_mount",value_cbuf.buf);

				everything_plugin_utf8_buf_kill(&remap_cbuf);
				everything_plugin_utf8_buf_kill(&value_cbuf);
			}
				
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_GET_OPTIONS_PAGE_MINMAX:
			
			((everything_plugin_get_options_page_minmax_t *)data)->wide = 200;
			((everything_plugin_get_options_page_minmax_t *)data)->high = 366;
			return (void *)1;
			
		case EVERYTHING_PLUGIN_PM_SIZE_OPTIONS_PAGE:
		
			{
				HWND page_hwnd;
				int static_wide;
				int button_wide;
				RECT rect;
				int x;
				int y;
				int wide;
				int high;
				int button_y;
				int userlist_high;
				int includeonlylist_high;
				
				page_hwnd = ((everything_plugin_size_options_page_t *)data)->page_hwnd;
				GetClientRect(page_hwnd,&rect);
				wide = rect.right - rect.left;
				high = rect.bottom - rect.top;
	
				wide = (wide * 96) / everything_plugin_os_get_logical_wide();
				high = (high * 96) / everything_plugin_os_get_logical_high();

				x = 12;
				y = 12;
				wide -= 24;
				high -= 24;
				
				static_wide = 0;
				static_wide = everything_server_expand_min_wide(page_hwnd,"Bind to &interfaces:",static_wide);
				static_wide = everything_server_expand_min_wide(page_hwnd,"&Port:",static_wide);
				static_wide += 6;

				/*
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_LICENSE1,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_LICENSE2,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_LICENSE3,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				*/
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_ENABLED_CHECKBOX,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_CHECKBOX_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_CHECKBOX_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_STATIC,x,y+3,static_wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_EDIT,x+static_wide,y,wide - (static_wide),EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PORT_STATIC,x,y+3,static_wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PORT_EDIT,x+static_wide,y,75,EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH);
				y += 27;
				
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_STATIC,x,y+3,static_wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				button_wide = 75 - 24;
				button_wide = everything_server_expand_min_wide(page_hwnd,"Add...",button_wide);
				button_wide = everything_server_expand_min_wide(page_hwnd,"Remove",button_wide);
				button_wide += 24;
				
				userlist_high = (high - (180)) / 2;
				includeonlylist_high = (high - (180)) - userlist_high;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,x,y,wide - button_wide - EVERYTHING_PLUGIN_OS_DLG_SEPARATOR,userlist_high);

				button_y = y;
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_ADD_BUTTON,x + wide - button_wide,button_y,button_wide,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
				button_y += EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_REMOVE_BUTTON,x + wide - button_wide,button_y,button_wide,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
				button_y += EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				y += userlist_high + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_GROUP,x,y,wide,12+6+21+6+15+6+includeonlylist_high+12);
				
				x += 12;
				y += 12 + 6;
				wide -= 12 + 12;
	
				static_wide = 0;
				static_wide = everything_server_expand_min_wide(page_hwnd,"Password:",static_wide);
				static_wide += 6;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_STATIC,x,y+3,static_wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,x+static_wide,y,wide-static_wide,EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_STATIC,x,y+3,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
				y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				button_wide = 75 - 24;
				button_wide = everything_server_expand_min_wide(page_hwnd,"Add...",button_wide);
				button_wide = everything_server_expand_min_wide(page_hwnd,"Edit...",button_wide);
				button_wide = everything_server_expand_min_wide(page_hwnd,"Remove",button_wide);
				button_wide += 24;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,x,y,wide - button_wide - EVERYTHING_PLUGIN_OS_DLG_SEPARATOR,includeonlylist_high);
				
				button_y = y;
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_ADD_BUTTON,x + wide - button_wide,button_y,button_wide,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
				button_y += EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_EDIT_BUTTON,x + wide - button_wide,button_y,button_wide,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
				button_y += EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				everything_plugin_os_set_dlg_rect(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_REMOVE_BUTTON,x + wide - button_wide,button_y,button_wide,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
				button_y += EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
				
				y += includeonlylist_high + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

				x -= 12;
				wide += 12 + 12;				
			}
			
			return (void *)1;

		case EVERYTHING_PLUGIN_PM_OPTIONS_PAGE_PROC:
		
			{
				HWND page_hwnd;
				
				page_hwnd = ((everything_plugin_options_page_proc_t *)data)->page_hwnd;
				
				switch(((everything_plugin_options_page_proc_t *)data)->msg)
				{
					case WM_VKEYTOITEM:

						switch(GetDlgCtrlID((HWND)((everything_plugin_options_page_proc_t *)data)->lParam))
						{
							case EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX:
							
								switch(LOWORD(((everything_plugin_options_page_proc_t *)data)->wParam))
								{
									case VK_DELETE:
										everything_server_remove_selected_user(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
										((everything_plugin_options_page_proc_t *)data)->result = -2;
										((everything_plugin_options_page_proc_t *)data)->handled = 1;
										return (void *)1;			

									case VK_F2:
										everything_server_edit_selected_user(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
										((everything_plugin_options_page_proc_t *)data)->result = -2;
										((everything_plugin_options_page_proc_t *)data)->handled = 1;
										return (void *)1;			
								}
							
								break;

							case EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX:
							
								switch(LOWORD(((everything_plugin_options_page_proc_t *)data)->wParam))
								{
									case VK_DELETE:
										everything_server_remove_selected_remap(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
										((everything_plugin_options_page_proc_t *)data)->result = -2;
										((everything_plugin_options_page_proc_t *)data)->handled = 1;
										return (void *)1;			

									case VK_F2:
										everything_server_edit_selected_remap(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
										((everything_plugin_options_page_proc_t *)data)->result = -2;
										((everything_plugin_options_page_proc_t *)data)->handled = 1;
										return (void *)1;			
								}
							
								break;
						}

						((everything_plugin_options_page_proc_t *)data)->result = -1;
						((everything_plugin_options_page_proc_t *)data)->handled = 1;
						return (void *)1;			
			 
			 		case WM_COMMAND:

						switch(LOWORD(((everything_plugin_options_page_proc_t *)data)->wParam))
						{
							/*
							case EVERYTHING_SERVER_PLUGIN_ID_LICENSE2:

								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == STN_CLICKED)
								{
									everything_plugin_os_open_url("https://www.voidtools.com/enterprise");
								}
								
								break;
						*/
							case EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX:
								
								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == LBN_DBLCLK)
								{
									everything_server_edit_selected_user(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								}
								else
								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == LBN_SELCHANGE)
								{
									everything_server_user_selection_changed(((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								}
								
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX:
								
								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == LBN_DBLCLK)
								{
									everything_server_edit_selected_remap(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								}
								else
								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == LBN_SELCHANGE)
								{
									everything_server_remap_selection_changed(((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								}
								
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_USER_ADD_BUTTON:
								everything_server_show_options_add_user_dialog(((everything_plugin_options_page_proc_t *)data)->options_hwnd,page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data,NULL);
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_USER_REMOVE_BUTTON:
								everything_server_remove_selected_user(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_REMAP_ADD_BUTTON:
								everything_server_show_options_add_remap_dialog(((everything_plugin_options_page_proc_t *)data)->options_hwnd,page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data,NULL);
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_REMAP_EDIT_BUTTON:
								everything_server_edit_selected_remap(((everything_plugin_options_page_proc_t *)data)->options_hwnd,page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_REMAP_REMOVE_BUTTON:
								everything_server_remove_selected_remap(((everything_plugin_options_page_proc_t *)data)->options_hwnd,page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_ENABLED_CHECKBOX:
								everything_server_update_options_page_buttons(page_hwnd);
								everything_server_enable_options_apply(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								break;
								
							case EVERYTHING_SERVER_PLUGIN_ID_PORT_EDIT:
							case EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_EDIT:
							
								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == EN_CHANGE)
								{
									everything_server_enable_options_apply(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								}

								break;

							case EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT:
							
								if (HIWORD(((everything_plugin_options_page_proc_t *)data)->wParam) == EN_CHANGE)
								{
									everything_server_user_setting_changed(((everything_plugin_options_page_proc_t *)data)->options_hwnd,((everything_plugin_options_page_proc_t *)data)->page_hwnd,((everything_plugin_options_page_proc_t *)data)->user_data);
								}

								break;
						}
					
						break;
					
				}
			}
			
			return (void *)1;			
	}
	
	return 0;
}

// MUST be called from main thread.
// start server
static void everything_server_start(void)
{
	if (!_everything_server)
	{
		HMODULE advapi32_hdll;

		advapi32_hdll = everything_plugin_os_load_system_library("advapi32.dll");
		if (advapi32_hdll)
		{
			BOOL (WINAPI *CryptAcquireContextW_proc)(void **phProv,LPCWSTR szContainer,LPCWSTR szProvider,DWORD dwProvType,DWORD dwFlags);	
			BOOL (WINAPI *CryptCreateHash_proc)(void *hProv,unsigned int Algid,void *hKey,DWORD dwFlags,void **phHash);
			BOOL (WINAPI *CryptHashData_proc)(void *hHash,CONST BYTE *pbData,DWORD dwDataLen,DWORD dwFlags);
			BOOL (WINAPI *CryptDeriveKey_proc)(void *hProv,unsigned int Algid,void *hBaseData,DWORD dwFlags,void **phKey);
			BOOL (WINAPI *CryptDestroyHash_proc)(void *hHash);
			BOOL (WINAPI *CryptReleaseContext_proc)(void *hProv,DWORD dwFlags);
			BOOL (WINAPI *CryptDestroyKey_proc)(void *hKey);
			BOOL (WINAPI *CryptEncrypt_proc)(void *hKey,void *hHash,BOOL Final,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen,DWORD dwBufLen);
			BOOL (WINAPI *CryptDecrypt_proc)(void *hKey,void *hHash,BOOL Final,DWORD dwFlags,BYTE *pbData,DWORD *pdwDataLen);
			
			CryptAcquireContextW_proc = (void *)GetProcAddress(advapi32_hdll,"CryptAcquireContextW");
			CryptCreateHash_proc = (void *)GetProcAddress(advapi32_hdll,"CryptCreateHash");
			CryptHashData_proc = (void *)GetProcAddress(advapi32_hdll,"CryptHashData");
			CryptDeriveKey_proc = (void *)GetProcAddress(advapi32_hdll,"CryptDeriveKey");
			CryptDestroyHash_proc = (void *)GetProcAddress(advapi32_hdll,"CryptDestroyHash");
			CryptReleaseContext_proc = (void *)GetProcAddress(advapi32_hdll,"CryptReleaseContext");
			CryptDestroyKey_proc = (void *)GetProcAddress(advapi32_hdll,"CryptDestroyKey");
			CryptEncrypt_proc = (void *)GetProcAddress(advapi32_hdll,"CryptEncrypt");
			CryptDecrypt_proc = (void *)GetProcAddress(advapi32_hdll,"CryptDecrypt");
		
			if ((CryptAcquireContextW_proc) && (CryptCreateHash_proc) && (CryptHashData_proc) && (CryptDeriveKey_proc) && (CryptDestroyHash_proc) && (CryptReleaseContext_proc) && (CryptDestroyKey_proc) && (CryptEncrypt_proc) && (CryptDecrypt_proc))
			{
				void *crypt_prov;
				
				if (CryptAcquireContextW_proc(&crypt_prov,NULL,NULL,EVERYTHING_SERVER_PROV_RSA_AES,EVERYTHING_SERVER_CRYPT_VERIFYCONTEXT))
				{
					int wsaret;
					EVERYTHING_PLUGIN_OS_WINSOCK_WSADATA wsadata;

					wsaret = everything_plugin_os_winsock_WSAStartup(MAKEWORD(1,1),&wsadata);
					if (wsaret == 0)
					{
						if ((LOBYTE(wsadata.wVersion) == 1) || (HIBYTE(wsadata.wVersion) == 1))
						{
							EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT listen_wakeup_event;
							
							listen_wakeup_event = everything_plugin_os_winsock_WSACreateEvent();
							
							if (listen_wakeup_event != EVERYTHING_PLUGIN_OS_WINSOCK_WSA_INVALID_EVENT)
							{
								EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT client_wakeup_event;
							
								client_wakeup_event = everything_plugin_os_winsock_WSACreateEvent();
								
								if (client_wakeup_event != EVERYTHING_PLUGIN_OS_WINSOCK_WSA_INVALID_EVENT)
								{
									// make server now, as it will hold the ref to WSAStartup.
									_everything_server = everything_plugin_mem_calloc(sizeof(everything_server_t));
									
									_everything_server->listen_terminate_event = everything_plugin_os_event_create();
									_everything_server->client_terminate_event = everything_plugin_os_event_create();
									_everything_server->listen_wakeup_event = listen_wakeup_event;
									_everything_server->client_wakeup_event = client_wakeup_event;
									
									_everything_server->advapi32_hdll = advapi32_hdll;
									_everything_server->CryptCreateHash_proc = CryptCreateHash_proc;
									_everything_server->CryptHashData_proc = CryptHashData_proc;
									_everything_server->CryptDeriveKey_proc = CryptDeriveKey_proc;
									_everything_server->CryptDestroyHash_proc = CryptDestroyHash_proc;
									_everything_server->CryptReleaseContext_proc = CryptReleaseContext_proc;
									_everything_server->CryptDestroyKey_proc = CryptDestroyKey_proc;
									_everything_server->CryptEncrypt_proc = CryptEncrypt_proc;
									_everything_server->CryptDecrypt_proc = CryptDecrypt_proc;
									_everything_server->crypt_prov = crypt_prov;
							
									// server owns handles now.
									advapi32_hdll = NULL;
									listen_wakeup_event = NULL;
									client_wakeup_event = NULL;
									wsaret = WSAEFAULT;
									crypt_prov = NULL;
									
									InitializeCriticalSection(&_everything_server->cs);

									_everything_server->db = everything_plugin_db_add_local_ref();

									_everything_server->bindings = everything_plugin_utf8_string_alloc_utf8_string(everything_server_bindings);
									_everything_server->port = everything_server_port;
									
									everything_server_user_list_copy(&_everything_server->user_list,&everything_server_user_list);
									
									// setup remapping array for each user:
									{
										everything_server_user_t *user;
										
										user = _everything_server->user_list.start;
										while(user)
										{
											everything_server_remap_t *esremap;
											everything_plugin_db_remap_list_t *remap_list;

											remap_list = everything_plugin_db_remap_list_create();

											esremap = user->remap_list.start;
											while(esremap)
											{
												everything_plugin_db_remap_list_add(remap_list,esremap->path,everything_plugin_utf8_string_get_length_in_bytes(esremap->path),esremap->mount,everything_plugin_utf8_string_get_length_in_bytes(esremap->mount));
												
												esremap = esremap->next;
											}
										
											user->remap_array = everything_plugin_db_remap_array_create(remap_list);
											if (user->remap_array)
											{
												user->remap_id = everything_plugin_db_remap_array_get_hashcode(user->remap_array);
											}
											else
											{
												user->remap_id = 0;
											}
										
											everything_plugin_db_remap_list_destroy(remap_list);
											
											user = user->next;
										}
									}
									
									_everything_server->journal_notification = everything_plugin_db_journal_notification_register(_everything_server->db,NULL,everything_server_journal_notification_callback_proc);
									
									// parse the list of bindings.

									if ((*everything_server_bindings) && (everything_plugin_utf8_string_compare(everything_server_bindings,"*") != 0))
									{
										const everything_plugin_utf8_t *bindp;
										everything_plugin_utf8_buf_t bind_cbuf;
										
										everything_plugin_utf8_buf_init(&bind_cbuf);
										
										bindp = everything_server_bindings;
									
										for(;;)
										{
											bindp = everything_plugin_utf8_string_parse_c_item(bindp,&bind_cbuf);
											if (!bindp)
											{
												break;
											}
											
											if (*bind_cbuf.buf)
											{
												everything_server_add_binding(bind_cbuf.buf);
											}
										}

										everything_plugin_utf8_buf_kill(&bind_cbuf);
									}
									else
									{
										everything_server_add_binding(NULL);
									}
									
									// did we bind to anything?
									_everything_server->listen_thread = everything_plugin_os_thread_create(everything_server_listen_thread_proc,NULL);
									_everything_server->client_thread = everything_plugin_os_thread_create(everything_server_client_thread_proc,NULL);

									if (client_wakeup_event)
									{
										everything_plugin_os_winsock_WSACloseEvent(client_wakeup_event);
									}
								}
								else
								{
									everything_plugin_debug_error_printf("WSACreateEvent failed %d\n",everything_plugin_os_winsock_WSAGetLastError());
								}
								
								if (listen_wakeup_event)
								{
									everything_plugin_os_winsock_WSACloseEvent(listen_wakeup_event);
								}
							}
							else
							{
								everything_plugin_debug_error_printf("WSACreateEvent failed %d\n",everything_plugin_os_winsock_WSAGetLastError());
							}
						}
						else
						{
							everything_plugin_debug_error_printf("unsupported WSA data format %d %d\n",LOBYTE(wsadata.wVersion),HIBYTE(wsadata.wVersion));
						}
							
						if (wsaret == 0)
						{
							everything_plugin_os_winsock_WSACleanup();
						}
					}
					else
					{
						everything_plugin_debug_error_printf("WSAStartup failed %d\n",wsaret);
					}
					
					if (crypt_prov)
					{
						CryptReleaseContext_proc(crypt_prov,0);
					}
				}
				else
				{
					everything_plugin_debug_error_printf("CryptAcquireContext %u\n",GetLastError());
				}
			}
			else
			{
				everything_plugin_debug_error_printf("Crypt API\n");
			}
		}
		else
		{
			everything_plugin_debug_error_printf("advapi32.dll %d\n",GetLastError());
		}
	}
}

// MUST be called from main thread.
// shutdown server
static void everything_server_shutdown(void)
{
	if (_everything_server)
	{
		// stop listening
		// ensure no more clients will be created.
		if (_everything_server->listen_thread)
		{
			SetEvent(_everything_server->listen_terminate_event);
			everything_plugin_os_winsock_WSASetEvent(_everything_server->listen_wakeup_event);

			everything_plugin_os_thread_cancel_synchronous_io(_everything_server->listen_thread);
			
			everything_plugin_os_thread_wait_and_close(_everything_server->listen_thread);
		}
		
		// destroy listening sockets.
		{
			everything_server_listen_t *l;
			everything_server_listen_t *next_l;

			l = _everything_server->listen_start;
			while(l)			
			{
				next_l = l->next;
				
				everything_plugin_os_winsock_closesocket(l->listen_socket);
				everything_plugin_os_winsock_WSACloseEvent(l->accept_event);
				everything_plugin_mem_free(l);
				
				l = next_l;
			}
		}
		
		// there's no more clients 
		// wait for the client update thread.
		// there might still be pending IO.
		if (_everything_server->client_thread)
		{
			SetEvent(_everything_server->client_terminate_event);
			everything_plugin_os_winsock_WSASetEvent(_everything_server->client_wakeup_event);
			
			everything_plugin_os_thread_cancel_synchronous_io(_everything_server->client_thread);

			everything_plugin_os_thread_wait_and_close(_everything_server->client_thread);
		}
		
		everything_plugin_db_journal_notification_unregister(_everything_server->journal_notification);

		everything_plugin_event_remove(everything_server_request_index_event_proc,NULL);
		everything_plugin_event_remove(everything_server_request_journal_event_proc,NULL);

		everything_plugin_db_onready_remove(_everything_server->db,everything_server_request_index_event_proc,NULL);
		everything_plugin_db_onready_remove(_everything_server->db,everything_server_request_journal_event_proc,NULL);

		everything_server_user_list_kill(&_everything_server->user_list);
	
		everything_plugin_db_release(_everything_server->db);
		
		everything_plugin_mem_free(_everything_server->bindings);

		CloseHandle(_everything_server->listen_terminate_event);
		CloseHandle(_everything_server->client_terminate_event);
		everything_plugin_os_winsock_WSACloseEvent(_everything_server->listen_wakeup_event);
		everything_plugin_os_winsock_WSACloseEvent(_everything_server->client_wakeup_event);
		
		_everything_server->CryptReleaseContext_proc(_everything_server->crypt_prov,0);

		DeleteCriticalSection(&_everything_server->cs);
		
		// there MUST be a WSACleanup
		everything_plugin_os_winsock_WSACleanup();
		
		FreeLibrary(_everything_server->advapi32_hdll);
		
		everything_plugin_mem_free(_everything_server);
		
		_everything_server = NULL;
	}
}

// insert the client
// MUST be fast.
static everything_server_client_t *everything_server_client_create(EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET socket_handle)
{
	everything_server_client_t *c;
	
	c = everything_plugin_mem_calloc(sizeof(everything_server_client_t));
	
	c->socket_handle = socket_handle;

	everything_plugin_interlocked_set(&c->completion_routine_ref_count,0);
	
	c->recv_overlapped.hEvent = c;
	c->send_overlapped.hEvent = c;
	
	if (_everything_server->client_start)
	{
		_everything_server->client_last->next = c;
		c->prev = _everything_server->client_last;
	}
	else
	{
		_everything_server->client_start = c;
		c->prev = NULL;
	}
	
	c->next = NULL;
	_everything_server->client_last = c;
	
	return c;
}

// free the client
static void everything_server_client_destroy(everything_server_client_t *c)
{
	// there is still a pending WSARecv.
	// make sure we close the socket now before freeing our buffers which would still be recving data.
	everything_plugin_os_winsock_closesocket(c->socket_handle);
	
	for(;;)
	{
		everything_plugin_os_winsock_WSAResetEvent(_everything_server->client_wakeup_event);
		
everything_plugin_debug_printf("closesocket wait for completion routine %zu\n",everything_plugin_interlocked_get(&c->completion_routine_ref_count));
		
		if (everything_plugin_interlocked_get(&c->completion_routine_ref_count) == 0)
		{
			break;
		}
	
		everything_plugin_os_winsock_WSAWaitForMultipleEvents(1,&_everything_server->client_wakeup_event,FALSE,INFINITE,TRUE);
	}
	
	everything_plugin_os_winsock_WSASetEvent(_everything_server->client_wakeup_event);
	
	EnterCriticalSection(&_everything_server->cs);
		
	// unlink.	
	if (c->prev)
	{
		c->prev->next = c->next;
	}
	else
	{
		_everything_server->client_start = c->next;
	}
	
	if (c->next)
	{
		c->next->prev = c->prev;
	}
	else
	{
		_everything_server->client_last = c->prev;
	}
	
	if (c->is_in_send_event_list)
	{
		if (c->send_event_prev)
		{
			c->send_event_prev->send_event_next = c->send_event_next;
		}
		else
		{
			_everything_server->client_send_event_start = c->send_event_next;
		}
		
		if (c->send_event_next)
		{
			c->send_event_next->send_event_prev = c->send_event_prev;
		}
		else
		{
			_everything_server->client_send_event_last = c->send_event_prev;
		}
	}
	
	if (c->is_in_recv_event_list)
	{
		if (c->recv_event_prev)
		{
			c->recv_event_prev->recv_event_next = c->recv_event_next;
		}
		else
		{
			_everything_server->client_recv_event_start = c->recv_event_next;
		}
		
		if (c->recv_event_next)
		{
			c->recv_event_next->recv_event_prev = c->recv_event_prev;
		}
		else
		{
			_everything_server->client_recv_event_last = c->recv_event_prev;
		}
	}

	if (c->is_in_index_request_list)
	{
		if (c->index_request_prev)
		{
			c->index_request_prev->index_request_next = c->index_request_next;
		}
		else
		{
			_everything_server->client_index_request_start = c->index_request_next;
		}
		
		if (c->index_request_next)
		{
			c->index_request_next->index_request_prev = c->index_request_prev;
		}
		else
		{
			_everything_server->client_index_request_last = c->index_request_prev;
		}
	}

	if (c->is_in_journal_request_list)
	{
		if (c->journal_request_prev)
		{
			c->journal_request_prev->journal_request_next = c->journal_request_next;
		}
		else
		{
			_everything_server->client_journal_request_start = c->journal_request_next;
		}
		
		if (c->journal_request_next)
		{
			c->journal_request_next->journal_request_prev = c->journal_request_prev;
		}
		else
		{
			_everything_server->client_journal_request_last = c->journal_request_prev;
		}
	}
	
	if (c->is_in_journal_notification_list)
	{
		if (c->journal_notification_prev)
		{
			c->journal_notification_prev->journal_notification_next = c->journal_notification_next;
		}
		else
		{
			_everything_server->client_journal_notification_start = c->journal_notification_next;
		}
		
		if (c->journal_notification_next)
		{
			c->journal_notification_next->journal_notification_prev = c->journal_notification_prev;
		}
		else
		{
			_everything_server->client_journal_notification_last = c->journal_notification_prev;
		}
	}

	LeaveCriticalSection(&_everything_server->cs);
		
	if (c->index_snapshot_file)
	{
		everything_plugin_db_snapshot_file_close(c->index_snapshot_file);
	}
	
	if (c->index_snapshot)
	{
		everything_server_index_snapshot_release(c->index_snapshot);
	}

	if (c->journal_file)
	{
		everything_plugin_db_journal_file_close(c->journal_file);
	}

	everything_server_client_free_send_buffer(c);
	
	if (c->crypt_decrypt_key)
	{
		_everything_server->CryptDestroyKey_proc(c->crypt_decrypt_key);
	}
	
	if (c->crypt_encrypt_key)
	{
		_everything_server->CryptDestroyKey_proc(c->crypt_encrypt_key);
	}
	
	everything_plugin_mem_free(c);
}

static int everything_server_is_config_change(void)
{
	if (_everything_server)
	{
		if (everything_server_port != _everything_server->port)
		{
			return 1;
		}

		if (everything_plugin_utf8_string_compare(everything_server_bindings,_everything_server->bindings) != 0)
		{
			return 1;
		}
		
		if (!everything_server_user_list_is_equal(&everything_server_user_list,&_everything_server->user_list))
		{
			return 1;
		}
	}
	
	return 0;
}

// MUST be called from main thread.
static int everything_server_apply_settings(void)
{
	if (everything_server_enabled)
	{
		if (everything_server_is_config_change())
		{
			everything_server_shutdown();
		}
		
		everything_server_start();
		
		if (_everything_server)
		{
			return 1;
		}
	}
	else
	{
		everything_server_shutdown();
		
		return 1;
	}
	
	return 0;
}

// get the localhost os_addrinfo
// save stack from main too.
static int everything_server_get_bind_addrinfo(const everything_plugin_utf8_t *nodename,struct everything_plugin_os_winsock_addrinfo **ai)
{
	struct everything_plugin_os_winsock_addrinfo hints;
	everything_plugin_utf8_buf_t port_cbuf;
	int ret;
	
	everything_plugin_utf8_buf_init(&port_cbuf);
	ret = 0;

	// Fill out the local socket address data.
	everything_plugin_os_zero_memory(&hints,sizeof(struct everything_plugin_os_winsock_addrinfo));
	hints.ai_protocol = EVERYTHING_PLUGIN_OS_WINSOCK_IPPROTO_TCP;
	hints.ai_socktype = EVERYTHING_PLUGIN_OS_WINSOCK_SOCK_STREAM;
	hints.ai_flags = EVERYTHING_PLUGIN_OS_WINSOCK_AI_PASSIVE;	

	everything_plugin_utf8_buf_printf(&port_cbuf,(const everything_plugin_utf8_t *)"%d",_everything_server->port);

	if (everything_plugin_os_winsock_getaddrinfo((const char *)nodename,(const char *)port_cbuf.buf,&hints,ai) == 0)
	{
		ret = 1;
	}

	everything_plugin_utf8_buf_kill(&port_cbuf);
	
	return ret;
}

static void everything_server_add_binding(const everything_plugin_utf8_t *nodename)
{
	struct everything_plugin_os_winsock_addrinfo *ai;
		
	if (everything_server_get_bind_addrinfo(nodename,&ai))
	{
		struct everything_plugin_os_winsock_addrinfo *aip;
		
		aip = ai;
		
		while(aip)
		{
			// ipv4 or ipv6 please.
			if ((aip->ai_family == EVERYTHING_PLUGIN_OS_WINSOCK_AF_INET) || (aip->ai_family == EVERYTHING_PLUGIN_OS_WINSOCK_AF_INET6))
			{
				EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET listen_socket;
				int ok;
				
				// reset ret, as a previous bind would have set it to 1.
				ok = 0;

	//DBEUG:
	everything_plugin_debug_printf((const everything_plugin_utf8_t *)"bind to family %d, protocol %d, socktype %d\n",aip->ai_family,aip->ai_protocol,aip->ai_socktype);

				listen_socket = everything_plugin_os_winsock_socket(aip->ai_family,aip->ai_socktype,aip->ai_protocol);
				if (listen_socket != EVERYTHING_PLUGIN_OS_WINSOCK_INVALID_SOCKET)
				{
					EVERYTHING_PLUGIN_OS_WINSOCK_WSAEVENT accept_event;
					
					accept_event = everything_plugin_os_winsock_WSACreateEvent();
					
					if (accept_event != EVERYTHING_PLUGIN_OS_WINSOCK_WSA_INVALID_EVENT)
					{
						if (everything_plugin_os_winsock_WSAEventSelect(listen_socket,accept_event,EVERYTHING_PLUGIN_OS_WINSOCK_FD_ACCEPT|EVERYTHING_PLUGIN_OS_WINSOCK_FD_CLOSE) != EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET_ERROR)
						{
							if (everything_plugin_os_winsock_bind(listen_socket,aip->ai_addr,(int)aip->ai_addrlen) != EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET_ERROR)
							{
								if (everything_plugin_os_winsock_listen(listen_socket,EVERYTHING_PLUGIN_OS_WINSOCK_SOMAXCONN) != EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET_ERROR)
								{
									everything_server_listen_t *l;
									
									// alloc
									l = everything_plugin_mem_alloc(sizeof(everything_server_listen_t));
									
									// init
									l->listen_socket = listen_socket;
									l->accept_event = accept_event;
									
									// insert
									if (_everything_server->listen_start)
									{
										_everything_server->listen_last->next = l;
									}
									else
									{
										_everything_server->listen_start = l;
									}
									
									l->next = 0;
									_everything_server->listen_last = l;
									
									ok = 1;
								}
								else
								{
									everything_plugin_debug_error_printf("listend failed %d\n",everything_plugin_os_winsock_WSAGetLastError());
								}
							}
							else
							{
								everything_plugin_debug_error_printf("bind failed %d\n",everything_plugin_os_winsock_WSAGetLastError());
							}
						}
						else
						{
							everything_plugin_debug_error_printf("failed to set nonblocking mode\n");
						}
						
						if (!ok)
						{
							everything_plugin_os_winsock_WSACloseEvent(accept_event);
						}
					}
					else
					{
						everything_plugin_debug_error_printf("failed to create wsaevent %d\n",everything_plugin_os_winsock_WSAGetLastError());
					}

					if (!ok)
					{
						everything_plugin_os_winsock_closesocket(listen_socket);
					}
				}
				else
				{
					everything_plugin_debug_error_printf("socket failed %d\n",everything_plugin_os_winsock_WSAGetLastError());
				}
			}			
			
			aip = aip->ai_next;
		}
		
		everything_plugin_os_winsock_freeaddrinfo(ai);
	}
}

static void everything_server_wait_list_init(everything_server_wait_list_t *wait_list)
{
	wait_list->count = 0;
	wait_list->overflow = 0;
}

static void everything_server_wait_list_add(everything_server_wait_list_t *wait_list,HANDLE handle)
{
	if (wait_list->count < EVERYTHING_PLUGIN_OS_WINSOCK_WSA_MAXIMUM_WAIT_EVENTS)
	{
		wait_list->handles[wait_list->count] = handle;
		wait_list->count++;
	}
	else
	{
		wait_list->overflow = 1;
	}
}

// will send lpCompletionRoutine (even if the recv completes immediately)
// returns 1 if recv is successful (pending or completes immediately)
// returns 0 on error.
static int everything_server_client_do_recv(everything_server_client_t *c)
{
	EVERYTHING_PLUGIN_OS_WINSOCK_WSABUF wsabuf;
	DWORD numread;
	DWORD recv_flags;
	
	wsabuf.buf = c->recv_p;
	wsabuf.len = c->recv_avail;
	recv_flags = 0;
	
everything_plugin_debug_printf("WSARecv %p\n",c->socket_handle);

	if (everything_plugin_os_winsock_WSARecv(c->socket_handle,&wsabuf,1,&numread,&recv_flags,&c->recv_overlapped,everything_server_recv_completion_routine) == EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET_ERROR)
	{
		DWORD last_error;
		
		last_error = everything_plugin_os_winsock_WSAGetLastError();
		
		if (last_error == EVERYTHING_PLUGIN_OS_WINSOCK_WSA_IO_PENDING)
		{
everything_plugin_debug_printf("EVERYTHING_PLUGIN_OS_WINSOCK_WSA_IO_PENDING %p\n",c->socket_handle);

			everything_plugin_interlocked_inc(&c->completion_routine_ref_count);
			
			return 1;
		}
		else
		if (last_error == WSAEWOULDBLOCK)
		{
			// try again later.
			everything_server_client_add_recv_event(c);
		}
		else
		{
			return 0;
		}
	}

	everything_plugin_interlocked_inc(&c->completion_routine_ref_count);
	
	return 1;
}

static void CALLBACK everything_server_recv_completion_routine(IN DWORD dwError,IN DWORD cbTransferred,IN EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED lpOverlapped,IN DWORD dwFlags)
{
	everything_server_client_t *c;
	
	c = (everything_server_client_t *)lpOverlapped->hEvent;
	
	everything_plugin_debug_printf("Recv complete %p %u %u %u\n",c->socket_handle,dwError,c->recv_avail,cbTransferred);
//	debug_hex_dump(c->recv_p,cbTransferred);
	
	if (dwError)
	{
		everything_plugin_debug_error_printf("client error while in recv\n",c,dwError,c->recv_avail,cbTransferred);
		
		c->state = EVERYTHING_SERVER_CLIENT_STATE_ERROR;
	}
	else
	if (!cbTransferred)
	{
		everything_plugin_debug_error_printf("client disconnected while in recv\n",c,dwError,c->recv_avail,cbTransferred);
		
		c->state = EVERYTHING_SERVER_CLIENT_STATE_ERROR;
	}
	else
	{
		c->recv_p += cbTransferred;
		c->recv_avail -= cbTransferred;
	}
	
	everything_plugin_interlocked_dec(&c->completion_routine_ref_count);
	
	everything_server_client_add_recv_event(c);
}

// this will process new connections only
// this must be fast as we need to empty the listen/accept queue as fast as possible, this queue is only 200 connections on Windows 7.
// needs to handle 10k connections / second.
static DWORD WINAPI everything_server_listen_thread_proc(void *param)
{
	for(;;)
	{
		everything_server_wait_list_t wait_list;
		DWORD wait_ret;

//everything_plugin_debug_printf("everything server listen awake\n");

		if (everything_plugin_os_event_is_set(_everything_server->listen_terminate_event))
		{
			break;
		}
		
		everything_server_wait_list_init(&wait_list);
		
		everything_plugin_os_winsock_WSAResetEvent(_everything_server->listen_wakeup_event);
		
		everything_server_wait_list_add(&wait_list,_everything_server->listen_wakeup_event);
		
		// be fair, give each bind a fair chance to accept.
		// calling accept is slow, avoid calling accept when it previously returned WSAEWOULDBLOCK.
		{
			everything_server_listen_t *l;
			
			l = _everything_server->listen_start;
			
			while(l)
			{
				EVERYTHING_PLUGIN_OS_WINSOCK_WSANETWORKEVENTS network_events;
				
				// WSAEnumNetworkEvents will reset the accept event.
				if (everything_plugin_os_winsock_WSAEnumNetworkEvents(l->listen_socket,l->accept_event,&network_events) != EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET_ERROR)
				{
					if (network_events.lNetworkEvents & EVERYTHING_PLUGIN_OS_WINSOCK_FD_CLOSE)
					{
//DEBUG_FIXME("does the event stay set? -if so wait would never sleep. do we recreate this listener? -do we kill this listener?");
					}
					else
					if (network_events.lNetworkEvents & EVERYTHING_PLUGIN_OS_WINSOCK_FD_ACCEPT)
					{
						for(;;)
						{
							EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET client_socket;
							
//			everything_plugin_debug_printf("ENTER accept\n");
							
							client_socket = everything_plugin_os_winsock_accept(l->listen_socket,0,0);

//			everything_plugin_debug_printf("LEAVE accept %d %d\n",client_socket,everything_plugin_os_winsock_WSAGetLastError());

							if (client_socket != EVERYTHING_PLUGIN_OS_WINSOCK_INVALID_SOCKET)
							{
								everything_server_client_t *c;
								
								everything_plugin_network_set_tcp_nodelay(client_socket);
								everything_plugin_network_set_keepalive(client_socket);
								everything_plugin_network_set_nonblocking(client_socket);
								
								c = everything_server_client_create(client_socket);
								
								everything_server_client_add_recv_event(c);
							}
							else
							{
								break;
							}
						}
					}
				}
			
				everything_server_wait_list_add(&wait_list,l->accept_event);
				
				l = l->next;
			}
		}
	
//everything_plugin_debug_printf("everything server listen wait %u\n",wait_list.count);

		wait_ret = everything_plugin_os_winsock_WSAWaitForMultipleEvents(wait_list.count,wait_list.handles,FALSE,wait_list.overflow ? 0 : INFINITE,TRUE);
		
		if (wait_list.overflow)
		{
			if (wait_ret == EVERYTHING_PLUGIN_OS_WINSOCK_WSA_WAIT_TIMEOUT)
			{
				// there should only be one or two bindings.
				// greater than 64 bindings, just poll...
				Sleep(0);
			}
		}
	}
	
	return 0;
}

static void everything_server_client_add_send_event(everything_server_client_t *c)
{
	EnterCriticalSection(&_everything_server->cs);
	
	if (!c->is_in_send_event_list)
	{
		if (_everything_server->client_send_event_start)
		{
			_everything_server->client_send_event_last->send_event_next = c;
			c->send_event_prev = _everything_server->client_send_event_last;
		}
		else
		{
			_everything_server->client_send_event_start = c;
			c->send_event_prev = NULL;
		}
		
		_everything_server->client_send_event_last = c;
		c->send_event_next = NULL;
		c->is_in_send_event_list = 1;
	}

	LeaveCriticalSection(&_everything_server->cs);

	everything_plugin_os_winsock_WSASetEvent(_everything_server->client_wakeup_event);	
}

static void everything_server_client_add_recv_event(everything_server_client_t *c)
{
	EnterCriticalSection(&_everything_server->cs);
	
	if (!c->is_in_recv_event_list)
	{
		if (_everything_server->client_recv_event_start)
		{
			_everything_server->client_recv_event_last->recv_event_next = c;
			c->recv_event_prev = _everything_server->client_recv_event_last;
		}
		else
		{
			_everything_server->client_recv_event_start = c;
			c->recv_event_prev = NULL;
		}
		
		_everything_server->client_recv_event_last = c;
		c->recv_event_next = NULL;
		c->is_in_recv_event_list = 1;
	}
	
	LeaveCriticalSection(&_everything_server->cs);

	everything_plugin_os_winsock_WSASetEvent(_everything_server->client_wakeup_event);
}

static int everything_server_client_update_send(everything_server_client_t *c)
{
	int ret;
	
	ret = 0;
			
	switch(c->state)
	{
		case EVERYTHING_SERVER_CLIENT_STATE_SEND_REPLY:

			if (c->send_avail)
			{
				// send more..
				if (everything_server_client_send_msg(c))
				{
					ret = 1;
				}
			}
			else
			{
				everything_server_client_free_send_buffer(c);
				
				// issue first read.
				if (everything_server_client_recv_next_command(c))
				{
					// read next command..
					c->state = EVERYTHING_SERVER_CLIENT_STATE_READ_COMMAND;
				
					ret = 1;
				}
			}
			
			break;
		
		case EVERYTHING_SERVER_CLIENT_STATE_SEND_INDEX:

			if (c->send_avail)
			{
				// send more..
				if (everything_server_client_send_msg(c))
				{
					ret = 1;
				}
			}
			else
			if (c->index_snapshot_avail)
			{
				everything_server_client_setup_send_next_index(c);

				if (everything_server_client_send_msg(c))
				{
					ret = 1;
				}
			}
			else
			{
				everything_server_client_free_send_buffer(c);
			
				// read next command..
				if (everything_server_client_recv_next_command(c))
				{
					// read next command..
					c->state = EVERYTHING_SERVER_CLIENT_STATE_READ_COMMAND;
				
					ret = 1;
				}
			}
			
			break;
									
		case EVERYTHING_SERVER_CLIENT_STATE_SEND_JOURNAL:

			if (c->send_avail)
			{
				// send more..
				if (everything_server_client_send_msg(c))
				{
					ret = 1;
				}
			}
			else
			{
				// DO NOT BREAK OUT OF THIS STATE.
				everything_server_client_request_next_journal(c);
				
				ret = 1;
			}

			break;
									
	}
	
	return ret;
}

static int everything_server_client_update_recv(everything_server_client_t *c)
{
	int ret;
	
	ret = 0;
			
	switch(c->state)
	{
		case EVERYTHING_SERVER_CLIENT_STATE_CONNECT:

			everything_plugin_debug_color_printf(0xff00ff00,"client %zu connected\n",c->socket_handle);

			c->recv_p = c->recv_stackbuf;
			c->recv_avail = sizeof(everything_server_msg_header_t);

			if (everything_server_client_do_recv(c))
			{
				c->state = EVERYTHING_SERVER_CLIENT_STATE_LOGIN_COMMAND;
				
				ret = 1;
			}

			break;
			
		case EVERYTHING_SERVER_CLIENT_STATE_LOGIN_COMMAND:	
		
			if (c->recv_avail)
			{
				// read more..
				if (everything_server_client_do_recv(c))
				{
					ret = 1;
				}
			}
			else
			{
				if (((everything_server_msg_header_t *)c->recv_stackbuf)->size == sizeof(everything_server_msg_header_t) + 272)
				{
					// allocate login read packet.
					if (everything_server_client_recv_data(c,c->recv_stackbuf,272))
					{
						c->state = EVERYTHING_SERVER_CLIENT_STATE_LOGIN_DATA;
						
						ret = 1;
					}
				}
			}
			
			break;
	
		case EVERYTHING_SERVER_CLIENT_STATE_LOGIN_DATA:

			if (c->recv_avail)
			{
				// read more..
				if (everything_server_client_do_recv(c))
				{
					ret = 1;
				}
			}
			else
			{
				if (everything_server_client_process_login(c))
				{
					ret = 1;
				}
			}
			
			break;
			
		case EVERYTHING_SERVER_CLIENT_STATE_READ_COMMAND:

			if (c->recv_avail)
			{
				// read more..
				if (everything_server_client_do_recv(c))
				{
					ret = 1;
				}
			}
			else
			{
				DWORD decrypt_len;
				
				decrypt_len = EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE;
				
				if (_everything_server->CryptDecrypt_proc(c->crypt_decrypt_key,0,FALSE,0,c->recv_stackbuf,&decrypt_len))
				{
					if (decrypt_len == EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE)
					{
						if (((everything_server_msg_header_t *)c->recv_stackbuf)->size > EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE)
						{
							DWORD padded_len;
							
							padded_len = (((everything_server_msg_header_t *)c->recv_stackbuf)->size + (EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE-1)) & (~(EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE-1));
							
							if (padded_len <= EVERYTHING_SERVER_MAX_RECV_SIZE)
							{
								// there's more data.
								if (everything_server_client_recv_data(c,c->recv_stackbuf + EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE,padded_len - EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE))
								{
									c->state = EVERYTHING_SERVER_CLIENT_STATE_READ_DATA;
									
									ret = 1;
								}
							}
						}
						else
						if (((everything_server_msg_header_t *)c->recv_stackbuf)->size >= sizeof(everything_server_msg_header_t))
						{
							// process the command.
							if (everything_server_client_process_command(c))
							{
								ret = 1;
							}
						}
					}
				}
			}
			
			break;
			

		case EVERYTHING_SERVER_CLIENT_STATE_READ_DATA:

			if (c->recv_avail)
			{
				// read more..
				if (everything_server_client_do_recv(c))
				{
					ret = 1;
				}
			}
			else
			{
				DWORD padded_len;
				DWORD decrypt_len;
						
				padded_len = (((everything_server_msg_header_t *)c->recv_stackbuf)->size + (EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE-1)) & (~(EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE-1));
				
				decrypt_len = padded_len - EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE;
				
				if (_everything_server->CryptDecrypt_proc(c->crypt_decrypt_key,0,FALSE,0,c->recv_stackbuf + EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE,&decrypt_len))
				{
					if (decrypt_len == padded_len - EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE)
					{
						if (everything_server_client_process_command(c))
						{
							ret = 1;
						}
					}
				}
			}
			
			break;	
									
	}
	
	return ret;
}

// closes all clients on exit
// make sure the listen thread exists before closing terminating.
// otherwise new clients might be created after we exit.
static DWORD WINAPI everything_server_client_thread_proc(void *param)
{
	for(;;)
	{
everything_plugin_debug_printf("everything server client awake\n");
	
		if (everything_plugin_os_event_is_set(_everything_server->client_terminate_event))
		{
			break;
		}
		
		everything_plugin_os_winsock_WSAResetEvent(_everything_server->client_wakeup_event);

		// process send events....
		for(;;)		
		{
			everything_server_client_t *c;
			
			EnterCriticalSection(&_everything_server->cs);
			c = _everything_server->client_send_event_start;
			if (c)
			{
				c->is_in_send_event_list = 0;
				
				_everything_server->client_send_event_start = c->send_event_next;
				if (!_everything_server->client_send_event_start)
				{
					_everything_server->client_send_event_last = NULL;
				}
			}

			LeaveCriticalSection(&_everything_server->cs);
			
			if (!c)
			{
				break;
			}
			
			if (!everything_server_client_update_send(c))
			{
everything_plugin_debug_error_printf("destroy client %zu\n",c->socket_handle);

				everything_server_client_destroy(c);
			}
		}
		
		// process recv events....
		for(;;)		
		{
			everything_server_client_t *c;
			
			EnterCriticalSection(&_everything_server->cs);
			c = _everything_server->client_recv_event_start;
			if (c)
			{
				c->is_in_recv_event_list = 0;
				
				_everything_server->client_recv_event_start = c->recv_event_next;
				if (!_everything_server->client_recv_event_start)
				{
					_everything_server->client_recv_event_last = NULL;
				}
			}

			LeaveCriticalSection(&_everything_server->cs);
			
			if (!c)
			{
				break;
			}
			
			if (!everything_server_client_update_recv(c))
			{
everything_plugin_debug_error_printf("destroy client %zu\n",c->socket_handle);

				everything_server_client_destroy(c);
			}
		}
	
everything_plugin_debug_printf("everything server client wait\n");

		everything_plugin_os_winsock_WSAWaitForMultipleEvents(1,&_everything_server->client_wakeup_event,FALSE,INFINITE,TRUE);
	}

everything_plugin_debug_printf("wait for completion routines\n");
	
	// wait for completion routines.

	// delete the clients.
	// do this before we close the thread.
	// otherwise the thread would continue to run forever.
	{
		for(;;)
		{
			everything_server_client_t *c;
			
			EnterCriticalSection(&_everything_server->cs);
			
			c = _everything_server->client_start;

			LeaveCriticalSection(&_everything_server->cs);
			
			if (!c)
			{
				break;
			}

			everything_server_client_destroy(c);
		}
	}

everything_plugin_debug_printf("thread exit\n");

	return 0;
}

static int everything_server_client_process_command(everything_server_client_t *c)
{
	int ret;
	BYTE *data_p;
	uintptr_t data_avail;
	DWORD command;
	
	ret = 0;

	data_p = c->recv_stackbuf;
	data_avail = ((everything_server_msg_header_t *)data_p)->size;
	command = ((everything_server_msg_header_t *)data_p)->command;
	
	data_p += sizeof(everything_server_msg_header_t);
	data_avail -= sizeof(everything_server_msg_header_t);
	
	switch(command)
	{
		case EVERYTHING_SERVER_COMMAND_ENUM_INDEX:
			
			if (data_avail == 0)
			{
				everything_server_client_request_index(c);
				
				c->state = EVERYTHING_SERVER_CLIENT_STATE_SEND_INDEX;
				
				ret = 1;
			}
			
			break;
			
		case EVERYTHING_SERVER_COMMAND_READ_JOURNAL:

			if (data_avail == sizeof(everything_server_journal_data_t))
			{
				everything_server_client_request_first_journal(c,((everything_server_journal_data_t *)data_p)->remap_id,((everything_server_journal_data_t *)data_p)->journal_id,((everything_server_journal_data_t *)data_p)->item_index);

				c->state = EVERYTHING_SERVER_CLIENT_STATE_SEND_JOURNAL;
					
				ret = 1;
			}
			
			break;
	}

	return ret;
}

static int everything_server_client_process_login(everything_server_client_t *c)
{
	int ret;
	everything_server_user_t *user;
	everything_plugin_utf8_buf_t key_cbuf;
	
	ret = 0;
	
	everything_plugin_utf8_buf_init(&key_cbuf);

	user = _everything_server->user_list.start;
	while(user)
	{
		void *crypt_decrypt_hash;
		
		if (c->user)
		{
			break;
		}
		
		if (_everything_server->CryptCreateHash_proc(_everything_server->crypt_prov,EVERYTHING_SERVER_CALG_SHA_256,0,0,&crypt_decrypt_hash))
		{
			BYTE salt[32] = {0x87,0x2F,0xF5,0x44,0x06,0xCA,0x06,0x55,0x0F,0x55,0x58,0x14,0xA2,0x35,0x3B,0xE5,0xA2,0xDA,0xE6,0x90,0x9C,0x32,0xBD,0xFA,0x3A,0xF4,0xE3,0xC6,0x83,0x30,0x9D,0xD8};

			everything_plugin_utf8_buf_printf(&key_cbuf,"%t%s",salt,32,user->password);
			
			if (key_cbuf.len <= EVERYTHING_PLUGIN_DWORD_MAX)
			{
				if (_everything_server->CryptHashData_proc(crypt_decrypt_hash,(BYTE*)key_cbuf.buf,(DWORD)key_cbuf.len,0))
				{
					void *crypt_decrypt_key;
					
					if (_everything_server->CryptDeriveKey_proc(_everything_server->crypt_prov,EVERYTHING_SERVER_CALG_AES_256,crypt_decrypt_hash,0,&crypt_decrypt_key)) 
					{
						DWORD decrypt_len;
						BYTE buf[272];
						
						everything_plugin_os_copy_memory(buf,c->recv_stackbuf,272);
						
						decrypt_len = 272;

						if (_everything_server->CryptDecrypt_proc(crypt_decrypt_key,0,FALSE,0,buf,&decrypt_len))
						{
							if (decrypt_len == 272)
							{
								uintptr_t name_len;
								
								name_len = *(DWORD *)buf;
								
								if (name_len == user->name_len)
								{
									if (name_len <= 272 - sizeof(DWORD))
									{
										if (everything_plugin_utf8_string_compare_nocase_n_n(user->name,user->name_len,buf + sizeof(DWORD),name_len) == 0)
										{
											if (everything_server_is_all_nuls(buf + sizeof(DWORD) + name_len,272 - sizeof(DWORD) - name_len))
											{
												void *crypt_encrypt_hash;

												if (_everything_server->CryptCreateHash_proc(_everything_server->crypt_prov,EVERYTHING_SERVER_CALG_SHA_256,0,0,&crypt_encrypt_hash))
												{
													if (_everything_server->CryptHashData_proc(crypt_encrypt_hash,(BYTE*)key_cbuf.buf,(DWORD)key_cbuf.len,0))
													{
														void *crypt_encrypt_key;
														
														if (_everything_server->CryptDeriveKey_proc(_everything_server->crypt_prov,EVERYTHING_SERVER_CALG_AES_256,crypt_encrypt_hash,0,&crypt_encrypt_key)) 
														{
															c->user = user;
															c->crypt_decrypt_key = crypt_decrypt_key;
															c->crypt_encrypt_key = crypt_encrypt_key;
															
															// client owns keys now.
															crypt_decrypt_key = NULL;
															crypt_encrypt_key = NULL;

															if (everything_server_client_send_reply(c,EVERYTHING_SERVER_REPLY_SUCCESS))
															{
																ret = 1;
															}
															
															if (crypt_encrypt_key)
															{
																_everything_server->CryptDestroyKey_proc(crypt_encrypt_key);
															}
														}
													}
													
													if (crypt_encrypt_hash)
													{
														_everything_server->CryptDestroyHash_proc(crypt_encrypt_hash);
													}
												}
											}
										}
									}
								}
							}
						}
						
						if (crypt_decrypt_key)
						{
							_everything_server->CryptDestroyKey_proc(crypt_decrypt_key);
						}
					}
				}
			}
			
			_everything_server->CryptDestroyHash_proc(crypt_decrypt_hash);
		}

		user = user->next;
	}	
	
	everything_plugin_utf8_buf_kill(&key_cbuf);
			
	return ret;
}

// caller must check size is > sizeof(everything_server_msg_header_t).
static int everything_server_client_recv_data(everything_server_client_t *c,void *data,DWORD size)
{
	c->recv_p = data;
	c->recv_avail = (DWORD)size;

	if (everything_server_client_do_recv(c))
	{
		return 1;
	}			
	
	return 0;
}

static int everything_server_client_recv_next_command(everything_server_client_t *c)
{
	c->recv_p = c->recv_stackbuf;
	c->recv_avail = EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE;

	if (everything_server_client_do_recv(c))
	{
		return 1;
	}
	
	return 0;
}

static int everything_server_client_send_msg(everything_server_client_t *c)
{
	EVERYTHING_PLUGIN_OS_WINSOCK_WSABUF wsabuf;
	DWORD numsend;
	
	wsabuf.buf = c->send_p;
	wsabuf.len = c->send_avail;
	
everything_plugin_debug_printf("WSASend %p\n",c->socket_handle);		

	if (everything_plugin_os_winsock_WSASend(c->socket_handle,&wsabuf,1,&numsend,0,&c->send_overlapped,everything_server_send_completion_routine) == EVERYTHING_PLUGIN_OS_WINSOCK_SOCKET_ERROR)
	{
		DWORD last_error;
		
		last_error = everything_plugin_os_winsock_WSAGetLastError();
		
		if (last_error == EVERYTHING_PLUGIN_OS_WINSOCK_WSA_IO_PENDING)
		{
everything_plugin_debug_printf("EVERYTHING_PLUGIN_OS_WINSOCK_WSA_IO_PENDING %p\n",c->socket_handle);		

			everything_plugin_interlocked_inc(&c->completion_routine_ref_count);
			
			return 1;
		}
		else
		if (last_error == WSAEWOULDBLOCK)
		{
			// try again later.
			everything_server_client_add_send_event(c);
		}
		else
		{
			return 0;
		}
	}
	
	everything_plugin_interlocked_inc(&c->completion_routine_ref_count);
	
	return 1;
}

static void CALLBACK everything_server_send_completion_routine(IN DWORD dwError,IN DWORD cbTransferred,IN EVERYTHING_PLUGIN_OS_WINSOCK_LPWSAOVERLAPPED lpOverlapped,IN DWORD dwFlags)
{
	everything_server_client_t *c;
	
	c = (everything_server_client_t *)lpOverlapped->hEvent;
	
	everything_plugin_debug_printf("Send complete %p %u %u %u\n",c->socket_handle,dwError,c->send_avail,cbTransferred);
//	debug_hex_dump(c->send_p,cbTransferred);

	if (dwError)
	{
		everything_plugin_debug_error_printf("client error while in send\n",c,dwError,c->send_avail,cbTransferred);
		
		c->state = EVERYTHING_SERVER_CLIENT_STATE_ERROR;
	}
	else
	if (!cbTransferred)
	{
		everything_plugin_debug_error_printf("client disconnected while in send\n",c,dwError,c->send_avail,cbTransferred);
		
		c->state = EVERYTHING_SERVER_CLIENT_STATE_ERROR;
	}

	c->send_p += cbTransferred;
	c->send_avail -= cbTransferred;

	everything_plugin_interlocked_dec(&c->completion_routine_ref_count);
	
	everything_server_client_add_send_event(c);
}

static void everything_server_client_setup_send_encrypt(everything_server_client_t *c,void *data,DWORD size)
{
	DWORD padded_len;
	DWORD encrypt_len;

	padded_len = (size + (EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE-1)) & (~(EVERYTHING_SERVER_ENCRYPT_BLOCK_SIZE-1));
	
	// pad data
	
	{
		uintptr_t pad_offset;
		
		pad_offset = size;
		
		while(pad_offset < padded_len)
		{
			((BYTE *)data)[pad_offset] = 0;
			
			pad_offset++;
		}
	}
	
	encrypt_len = padded_len;
	
	if (!_everything_server->CryptEncrypt_proc(c->crypt_encrypt_key,0,FALSE,0,data,&encrypt_len,padded_len))
	{
		EVERYTHING_SERVER_DEBUG_FATAL("CryptEncrypt %u",GetLastError());
	}
	
	if (encrypt_len != padded_len)
	{
		EVERYTHING_SERVER_DEBUG_FATAL("encrypt_len != padded_len");
	}
	
	c->send_p = data;
	c->send_avail = padded_len;
}

static int everything_server_client_send_reply(everything_server_client_t *c,DWORD command)
{
	((everything_server_msg_header_t *)c->send_stackbuf)->size = sizeof(everything_server_msg_header_t);
	((everything_server_msg_header_t *)c->send_stackbuf)->command = command;
	
	everything_server_client_setup_send_encrypt(c,c->send_stackbuf,sizeof(everything_server_msg_header_t));
	
	if (everything_server_client_send_msg(c))
	{
		c->state = EVERYTHING_SERVER_CLIENT_STATE_SEND_REPLY;
		
		return 1;
	}
	
	return 0;
}

// returns nonzero if the index_snapshot is available now
// returns zero if the index_snapshot is pending.
static void everything_server_client_request_index(everything_server_client_t *c)
{
	EnterCriticalSection(&_everything_server->cs);
				
	// add to index_snapshot notify event list.
	if (!c->is_in_index_request_list)
	{
everything_plugin_debug_color_printf(0xff00ff00,"requesting index_snapshot\n");

		if (_everything_server->client_index_request_start)
		{
			_everything_server->client_index_request_last->index_request_next = c;
			c->index_request_prev = _everything_server->client_index_request_last;
		}
		else
		{
			_everything_server->client_index_request_start = c;
			c->index_request_prev = NULL;

			everything_plugin_debug_color_printf(0xff00ff00,"post everything_server_request_index_event_proc\n");

			everything_plugin_event_post(everything_server_request_index_event_proc,NULL);
		}
		
		_everything_server->client_index_request_last = c;
		c->index_request_next = NULL;
		
		c->is_in_index_request_list = 1;
	}		
	
	LeaveCriticalSection(&_everything_server->cs);
}

// called from main thread.
static void WINAPI everything_server_request_index_event_proc(void *param)
{
everything_plugin_debug_color_printf(0xff00ff00,"everything_server_request_index_event_proc\n");

	// is the db busy?
	// try again later.
	if (everything_plugin_db_would_block(_everything_server->db))
	{
		everything_plugin_debug_color_printf(0xff00ff00,"DB WOULD BLOCK\n");
		
		everything_plugin_db_onready_add(_everything_server->db,everything_server_request_index_event_proc,NULL);
	}
	else
	{
		// _everything_server->index_snapshot can only change in main thread.

		// everything_plugin_db_snapshot_is_out_of_date will call DB_WAIT below.

		// already have index snapshot.
		// everything_server_request_index_event_proc can be posted multiple times if
		// a client makes a request, client is deleted (request list is cleared), a new clients makes a request.
		EnterCriticalSection(&_everything_server->cs);

		// notify clients.
		{
			everything_server_client_t *c;
			
			c = _everything_server->client_index_request_start;
			_everything_server->client_index_request_start = NULL;
			_everything_server->client_index_request_last = NULL;
			
			while(c)
			{
				c->is_in_index_request_list = 0;
				
				// check if the index is out of date.
				if (c->user->index_snapshot)
				{
					if (everything_plugin_db_snapshot_is_out_of_date(c->user->index_snapshot->db_snapshot,_everything_server->db,c->user->remap_array))
					{
						everything_plugin_debug_color_printf(0xff00ff00,"snapshot cache out of date\n");
						
						if (c->index_snapshot_file)
						{
							everything_plugin_db_snapshot_file_close(c->index_snapshot_file);
							
							c->index_snapshot_file = NULL;
						}
						
						everything_server_index_snapshot_release(c->user->index_snapshot);
						everything_plugin_timer_destroy(c->user->index_snapshot_expire_timer);
						
						c->user->index_snapshot = NULL;
						c->user->index_snapshot_expire_timer = NULL;
					}
				}

				if (!c->user->index_snapshot)
				{
					c->user->index_snapshot = everything_plugin_mem_alloc(sizeof(everything_server_index_snapshot_t));

					c->user->index_snapshot->db_snapshot = everything_plugin_db_snapshot_create(_everything_server->db,c->user->remap_array);

					everything_plugin_interlocked_set(&c->user->index_snapshot->ref_count,1);

					// keep this index_snapshot for x minutes..
					c->user->index_snapshot_expire_timer = everything_plugin_timer_create(everything_server_index_snapshot_expire_timer_proc,c->user,60000);
				}
			
	everything_plugin_debug_color_printf(0xff00ff00,"index_snapshot notify client %zu\n",c->socket_handle);

				everything_server_client_setup_send_first_index(c);
			
				everything_server_client_add_send_event(c);

				c = c->index_request_next;
			}
		}

		LeaveCriticalSection(&_everything_server->cs);
	}
}

// _everything_server->index_snapshot MUST be created before call.
static void everything_server_client_setup_send_first_index(everything_server_client_t *c)
{
	uintptr_t index_snapshot_size;
	
	c->index_snapshot = c->user->index_snapshot;

	everything_server_index_snapshot_add_ref(c->index_snapshot);

	index_snapshot_size = everything_plugin_db_snapshot_get_size(c->index_snapshot->db_snapshot);
	
	c->send_buffer = everything_plugin_mem_alloc(EVERYTHING_SERVER_MAX_SEND_SIZE);
	
	if (c->index_snapshot_file)
	{
		everything_plugin_db_snapshot_file_close(c->index_snapshot_file);
		
		c->index_snapshot_file = NULL;
	}
	
	c->index_snapshot_file = everything_plugin_db_snapshot_file_open(c->index_snapshot->db_snapshot);
	c->index_snapshot_avail = index_snapshot_size;
	
	everything_server_client_setup_send_next_index(c);
}

static void everything_server_client_setup_send_next_index(everything_server_client_t *c)
{
	DWORD send_size;
	uintptr_t numread;
	
	numread = everything_plugin_db_snapshot_file_read(c->index_snapshot_file,((BYTE *)c->send_buffer) + sizeof(everything_server_msg_header_t),EVERYTHING_SERVER_MAX_SEND_SIZE - sizeof(everything_server_msg_header_t));
	
	send_size = sizeof(everything_server_msg_header_t) + (DWORD)numread;
	
	c->send_buffer->size = send_size;
	c->index_snapshot_avail -= numread;
	c->send_buffer->command = c->index_snapshot_avail ? EVERYTHING_SERVER_REPLY_SUCCESS_MORE_DATA : EVERYTHING_SERVER_REPLY_SUCCESS;
	
	everything_server_client_setup_send_encrypt(c,(BYTE *)c->send_buffer,send_size);
	
	if (!c->index_snapshot_avail)
	{
		if (c->index_snapshot_file)
		{
			everything_plugin_db_snapshot_file_close(c->index_snapshot_file);
			
			c->index_snapshot_file = NULL;
		}

		// we are done with the index_snapshot.
		everything_server_index_snapshot_release(c->index_snapshot);
		
		c->index_snapshot = NULL;
	}
}

static void everything_server_client_request_first_journal(everything_server_client_t *c,EVERYTHING_PLUGIN_QWORD remap_id,EVERYTHING_PLUGIN_QWORD journal_id,EVERYTHING_PLUGIN_QWORD item_index)
{
	EnterCriticalSection(&_everything_server->cs);
				
	// add to journal_snapshot notify event list.
	if (!c->is_in_journal_request_list)
	{
		if (_everything_server->client_journal_request_start)
		{
			_everything_server->client_journal_request_last->journal_request_next = c;
			c->journal_request_prev = _everything_server->client_journal_request_last;
		}
		else
		{
			_everything_server->client_journal_request_start = c;
			c->journal_request_prev = NULL;

everything_plugin_debug_color_printf(0xff00ff00,"post everything_server_request_journal_event_proc\n");

			everything_plugin_event_post(everything_server_request_journal_event_proc,NULL);
		}
		
		_everything_server->client_journal_request_last = c;
		c->journal_request_next = NULL;
		
		c->is_in_journal_request_list = 1;
		
		c->journal_request_remap_id = remap_id;
		c->journal_request_journal_id = journal_id;
		c->journal_request_item_index = item_index;
	}		
	
	LeaveCriticalSection(&_everything_server->cs);
}

static void everything_server_client_request_next_journal(everything_server_client_t *c)
{
	EnterCriticalSection(&_everything_server->cs);
				
	// add to journal_snapshot notify event list.
	if (!c->is_in_journal_request_list)
	{
		if (_everything_server->client_journal_request_start)
		{
			_everything_server->client_journal_request_last->journal_request_next = c;
			c->journal_request_prev = _everything_server->client_journal_request_last;
		}
		else
		{
			_everything_server->client_journal_request_start = c;
			c->journal_request_prev = NULL;

everything_plugin_debug_color_printf(0xff00ff00,"post everything_server_request_journal_event_proc\n");

			everything_plugin_event_post(everything_server_request_journal_event_proc,NULL);
		}
		
		_everything_server->client_journal_request_last = c;
		c->journal_request_next = NULL;
		
		c->is_in_journal_request_list = 1;
	}		
	
	LeaveCriticalSection(&_everything_server->cs);
}

static void WINAPI everything_server_request_journal_event_proc(void *param)
{
//everything_plugin_debug_color_printf(0xff00ff00,"everything_server_request_journal_event_proc\n");

	// is the db busy?
	// try again later.
	if (everything_plugin_db_would_block(_everything_server->db))
	{
		everything_plugin_debug_color_printf(0xff00ff00,"DB WOULD BLOCK\n");
		
		everything_plugin_db_onready_add(_everything_server->db,everything_server_request_journal_event_proc,NULL);
	}
	else
	{
		// the db_* calls below will call DB_WAIT.
	
		EnterCriticalSection(&_everything_server->cs);
		
		{
			everything_server_client_t *c;
			
			c = _everything_server->client_journal_request_start;
			_everything_server->client_journal_request_start = NULL;
			_everything_server->client_journal_request_last = NULL;
			
			while(c)
			{
				uintptr_t numread;
				
				c->is_in_journal_request_list = 0;

				if (!c->journal_file)
				{
					if (c->user->remap_id == c->journal_request_remap_id)
					{
						c->journal_file = everything_plugin_db_journal_file_open(_everything_server->db,c->user->remap_array,c->journal_request_journal_id,c->journal_request_item_index);
					}
					else
					{
everything_plugin_debug_color_printf(0xff00ff00,"JOURNAL remap id changed\n");
					}

					c->send_buffer = everything_plugin_mem_alloc(EVERYTHING_SERVER_MAX_SEND_SIZE);
				}
				
everything_plugin_debug_color_printf(0xff00ff00,"JOURNAL %p %p\n",c->socket_handle,c->journal_file);
				
				if (!c->journal_file)
				{
					((everything_server_msg_header_t *)c->send_stackbuf)->size = sizeof(everything_server_msg_header_t);
					((everything_server_msg_header_t *)c->send_stackbuf)->command = EVERYTHING_SERVER_REPLY_ERROR_JOURNAL_ENTRY_NOT_FOUND;

					everything_server_client_setup_send_encrypt(c,c->send_stackbuf,sizeof(everything_server_msg_header_t));
					
					c->state = EVERYTHING_SERVER_CLIENT_STATE_SEND_REPLY;
					
					// get client update thread to send data.
					// don't send it here.
					everything_server_client_add_send_event(c);
				}
				else
				if (everything_plugin_db_journal_file_would_block(c->journal_file))
				{
					// change is pending.
					everything_plugin_debug_color_printf(0xff00ff00,"read journal would block\n");
					
					if (!c->is_in_journal_notification_list)
					{
						if (_everything_server->client_journal_notification_start)
						{
							_everything_server->client_journal_notification_last->journal_notification_next = c;
							c->journal_notification_prev = _everything_server->client_journal_notification_last;
						}
						else
						{
							_everything_server->client_journal_notification_start = c;
							c->journal_notification_prev = NULL;
						}
						
						_everything_server->client_journal_notification_last = c;
						c->journal_notification_next = NULL;
						
						c->is_in_journal_notification_list = 1;
					}
				}
				else
				if (everything_plugin_db_journal_file_read(c->journal_file,((BYTE *)c->send_buffer) + sizeof(everything_server_msg_header_t),EVERYTHING_SERVER_MAX_SEND_SIZE - sizeof(everything_server_msg_header_t),&numread))
				{
					c->send_buffer->size = (DWORD)(numread + sizeof(everything_server_msg_header_t));
					c->send_buffer->command = EVERYTHING_SERVER_REPLY_SUCCESS_MORE_DATA;
					
					everything_server_client_setup_send_encrypt(c,c->send_buffer,(DWORD)(numread + sizeof(everything_server_msg_header_t)));

everything_plugin_debug_color_printf(0xff00ff00,"journal file read %zu\n",numread);
					
					everything_server_client_add_send_event(c);
				}
				else
				{
					// journal item deleted while reading.
					// disconnect client, hopefully they reconnect and re-attempt journal read
					// next time they would get a journal item deleted error.
					c->state = EVERYTHING_SERVER_CLIENT_STATE_ERROR;

					everything_server_client_add_send_event(c);
				}

				c = c->journal_request_next;
			}
		}
		
		LeaveCriticalSection(&_everything_server->cs);
	}
}

static void WINAPI everything_server_journal_notification_callback_proc(void *param)
{
//	everything_plugin_debug_printf("journal notification\n");

	EnterCriticalSection(&_everything_server->cs);
	
	{
		everything_server_client_t *c;
		
		c = _everything_server->client_journal_notification_start;
		_everything_server->client_journal_notification_start = NULL;
		_everything_server->client_journal_notification_last = NULL;
		
		while(c)
		{
			c->is_in_journal_notification_list = 0;
			
			everything_server_client_request_next_journal(c);

			c = c->journal_notification_next;
		}
	}

	LeaveCriticalSection(&_everything_server->cs);
}

static void everything_server_index_snapshot_release(everything_server_index_snapshot_t *index_snapshot)
{
everything_plugin_debug_color_printf(0xff00ff00,"everything_server_index_snapshot_release %zu\n",everything_plugin_interlocked_get(&index_snapshot->ref_count));

	if (everything_plugin_interlocked_dec(&index_snapshot->ref_count) == 0)
	{
everything_plugin_debug_color_printf(0xff00ff00,"everything_server_index_snapshot_destroy\n");

		everything_plugin_db_snapshot_destroy(index_snapshot->db_snapshot);
		
		// timer is managed by server ref.
		
		everything_plugin_mem_free(index_snapshot);
	}
}

static void everything_server_index_snapshot_add_ref(everything_server_index_snapshot_t *index_snapshot)
{
	everything_plugin_interlocked_inc(&index_snapshot->ref_count);
}

static void EVERYTHING_PLUGIN_API everything_server_index_snapshot_expire_timer_proc(everything_server_user_t *user)
{
everything_plugin_debug_color_printf(0xff00ff00,"everything_server_index_snapshot_expire_timer_proc\n");

	everything_plugin_timer_destroy(user->index_snapshot_expire_timer);
	
	user->index_snapshot_expire_timer = NULL;
	
	EnterCriticalSection(&_everything_server->cs);
	
	everything_server_index_snapshot_release(user->index_snapshot);
	
	user->index_snapshot = NULL;
	
	LeaveCriticalSection(&_everything_server->cs);
}

static void everything_server_client_free_send_buffer(everything_server_client_t *c)
{
	if (c->send_buffer)
	{
		everything_plugin_mem_free(c->send_buffer);
		
		c->send_buffer = NULL;
	}
}

static void everything_server_update_options_page_user_list(HWND page_hwnd,everything_server_options_t *options,int select_index)
{
	everything_server_user_t *user;
	int count;
	
	everything_plugin_os_set_dlg_redraw(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,0);
	
	everything_plugin_os_clear_listbox(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX);
	count = 0;
	
	user = options->user_list.start;
	while(user)
	{
		everything_plugin_os_add_listbox_string_and_data(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,user->name_len ? user->name : "(empty)",user);
		
		count++;
		user = user->next;
	}
	
	if (count)
	{
		if (select_index > count-1)
		{
			select_index = count-1;
		}
		
		everything_plugin_os_set_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,select_index);
	}
	
	everything_plugin_os_set_dlg_redraw(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,1);
	
	everything_server_user_selection_changed(page_hwnd,options);
}

// user can be NULL.
static void everything_server_update_options_page_remap_list(HWND page_hwnd,everything_server_options_t *options,everything_server_user_t *user,int select_index)
{
	int count;
	
	everything_plugin_os_set_dlg_redraw(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,0);
	
	everything_plugin_os_clear_listbox(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX);
	count = 0;
	
	if (user)
	{
		everything_server_remap_t *remap;
		everything_plugin_utf8_buf_t text_cbuf;

		everything_plugin_utf8_buf_init(&text_cbuf);
		
		remap = user->remap_list.start;
		while(remap)
		{
			const everything_plugin_utf8_t *text;
			
			if (*remap->mount)
			{
				everything_plugin_utf8_buf_printf(&text_cbuf,"%s (%s)",remap->path,remap->mount);

				text = text_cbuf.buf;
			}
			else
			{
				text = remap->path;
			}
		
			everything_plugin_os_add_listbox_string_and_data(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,text,remap);
			
			count++;
			remap = remap->next;
		}

		everything_plugin_utf8_buf_kill(&text_cbuf);
	}
	
	if (count)
	{
		if (select_index > count-1)
		{
			select_index = count-1;
		}
		
		everything_plugin_os_set_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,select_index);
	}
	
	everything_plugin_os_set_dlg_redraw(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,1);
	
	everything_server_remap_selection_changed(page_hwnd,options);
}

static void everything_server_update_options_page_buttons(HWND page_hwnd)
{
	int user_index;
	int remap_index;
	int is_enabled;
	int is_user_enabled;
	int is_remap_enabled;
	
	user_index = -1;
	remap_index = -1;
	
	is_enabled = 0;
	is_user_enabled = 0;
	is_remap_enabled = 0;
	
	if (IsDlgButtonChecked(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_ENABLED_CHECKBOX) == BST_CHECKED)
	{
		is_enabled = 1;

		user_index = everything_plugin_os_get_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX);
				
		if (user_index >= 0)
		{
			is_user_enabled = 1;

			remap_index = everything_plugin_os_get_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX);
		
			if (remap_index >= 0)
			{
				is_remap_enabled = 1;
			}
		}
	}

	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_STATIC,is_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_BINDINGS_EDIT,is_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PORT_STATIC,is_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PORT_EDIT,is_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_STATIC,is_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,is_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_ADD_BUTTON,is_enabled);

	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_REMOVE_BUTTON,is_user_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_GROUP,is_user_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_STATIC,is_user_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,is_user_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_STATIC,is_user_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,is_user_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_ADD_BUTTON,is_user_enabled);
	
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_EDIT_BUTTON,is_remap_enabled);
	everything_plugin_os_enable_or_disable_dlg_item(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_REMOVE_BUTTON,is_remap_enabled);
}

static void everything_server_create_options_checkbox(everything_plugin_load_options_page_t *load_options_page,int id,DWORD extra_style,const everything_plugin_utf8_t *text,const everything_plugin_utf8_t *tooltip,int checked)
{
	everything_plugin_os_create_checkbox(load_options_page->page_hwnd,id,extra_style,checked,text);

	everything_plugin_os_add_tooltip(load_options_page->tooltip_hwnd,load_options_page->page_hwnd,id,tooltip);
}

static void everything_server_create_options_static(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *text)
{
	everything_plugin_os_create_static(load_options_page->page_hwnd,id,SS_LEFTNOWORDWRAP|WS_GROUP|SS_NOTIFY,text);
}

static void everything_server_create_options_edit(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *tooltip,const everything_plugin_utf8_t *text)
{
	everything_plugin_os_create_edit(load_options_page->page_hwnd,id,WS_GROUP,text);

	everything_plugin_os_add_tooltip(load_options_page->tooltip_hwnd,load_options_page->page_hwnd,id,tooltip);
}

static void everything_server_create_options_number_edit(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *tooltip,int value)
{
	everything_plugin_os_create_number_edit(load_options_page->page_hwnd,id,WS_GROUP,value);

	everything_plugin_os_add_tooltip(load_options_page->tooltip_hwnd,load_options_page->page_hwnd,id,tooltip);
}

static void everything_server_create_options_password_edit(everything_plugin_load_options_page_t *load_options_page,int id,const everything_plugin_utf8_t *tooltip,const everything_plugin_utf8_t *text)
{
	everything_plugin_os_create_password_edit(load_options_page->page_hwnd,id,WS_GROUP,text);

	everything_plugin_os_add_tooltip(load_options_page->tooltip_hwnd,load_options_page->page_hwnd,id,tooltip);
}

static void everything_server_create_options_button(everything_plugin_load_options_page_t *load_options_page,int id,DWORD extra_style,const everything_plugin_utf8_t *text,const everything_plugin_utf8_t *tooltip)
{
	everything_plugin_os_create_button(load_options_page->page_hwnd,id,extra_style,text);

	everything_plugin_os_add_tooltip(load_options_page->tooltip_hwnd,load_options_page->page_hwnd,id,tooltip);
}

static void everything_server_enable_options_apply(HWND options_hwnd,everything_server_options_t *options)
{
	if (!options->disallow_enable_apply)
	{
		everything_plugin_os_enable_or_disable_dlg_item(options_hwnd,1001,1);
	}
}

static int everything_server_expand_min_wide(HWND page_hwnd,const everything_plugin_utf8_t *text,int current_wide)
{
	int wide;
	
	wide = everything_plugin_os_expand_dialog_text_logical_wide_no_prefix(page_hwnd,text,current_wide);
	
	if (wide > current_wide)
	{
		return wide;
	}
	
	return current_wide;
}

static everything_plugin_utf8_t *everything_server_get_options_text(HWND page_hwnd,int id,everything_plugin_utf8_t *old_value)
{
	everything_plugin_utf8_buf_t cbuf;
	everything_plugin_utf8_t *ret;

	everything_plugin_utf8_buf_init(&cbuf);
	
	everything_plugin_os_get_dlg_text(page_hwnd,id,&cbuf);
	
	ret = everything_plugin_utf8_string_realloc_utf8_string(old_value,cbuf.buf);

	everything_plugin_utf8_buf_kill(&cbuf);
	
	return ret;
}

// index can be < 0
static everything_server_user_t *everything_server_user_from_index(HWND page_hwnd,int index)
{
	if (index >= 0)
	{
		return everything_plugin_os_get_listbox_data(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX,index);
	}
	
	return NULL;
}

// index can be < 0
static everything_server_remap_t *everything_server_remap_from_index(HWND page_hwnd,int index)
{
	if (index >= 0)
	{
		return everything_plugin_os_get_listbox_data(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX,index);
	}
	
	return NULL;
}

static INT_PTR __stdcall everything_server_options_add_user_dialog_proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
	everything_server_options_add_user_t *new_dialog;
	
	new_dialog = everything_plugin_os_get_window_user_data(hwnd);

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			int x;
			int y;
			int wide;
			int high;
			const everything_plugin_utf8_t *name;
			
			new_dialog = (everything_server_options_add_user_t *)lParam;
			
			new_dialog->hwnd = hwnd;
			
			// save lparam			
			everything_plugin_os_set_window_user_data(hwnd,new_dialog);

			wide = 384;
			high = 98;
		
			everything_plugin_os_center_dialog(GetParent(hwnd),hwnd,wide,high);
			
			x = 12;
			y = 12;
			wide -= 12*2;
			high -= 12*2;

			// create a blank edit
			everything_plugin_os_create_static(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_STATIC,SS_LEFTNOWORDWRAP|WS_GROUP,"Name:");
			everything_plugin_os_set_dlg_rect(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_STATIC,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
			
			y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_STATIC_SEPARATOR;
			
			name =	(const everything_plugin_utf8_t *)"";
		
			if (new_dialog->existing_user)
			{	
				name = new_dialog->existing_user->name;
			}

			// create a blank edit
			everything_plugin_os_create_edit(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_EDIT,WS_GROUP,name);
			everything_plugin_os_set_dlg_rect(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_EDIT,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH);
			everything_plugin_os_force_ltr_edit(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_EDIT);
			y += EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
			y += EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

			// ok, cancel.
			everything_plugin_os_create_button(hwnd,IDOK,WS_GROUP,everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_OK));
			everything_plugin_os_set_dlg_rect(hwnd,IDOK,x + wide + 6 - ((75 + 6) * 2),y,75,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
			everything_plugin_os_set_default_button(hwnd,IDOK);
			everything_plugin_os_create_button(hwnd,IDCANCEL,0,everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_CANCEL));
			everything_plugin_os_set_dlg_rect(hwnd,IDCANCEL,x + wide + 6 - ((75 + 6) * 1),y,75,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);

			if (everything_plugin_config_get_int_value("tooltips"))
			{
				// create tooltip window
				new_dialog->tooltip_hwnd = everything_plugin_os_create_tooltip();
				
				// setup help
				everything_plugin_os_add_tooltip(new_dialog->tooltip_hwnd,hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_EDIT,"The username to give access.\nCan be empty.");
			}

			// return true to focus the first dlg control.
			return TRUE;
		}
		
		case WM_COMMAND: 
		
			switch(LOWORD(wParam))
			{
				case IDOK:

					{
						everything_plugin_utf8_buf_t name_cbuf;
						everything_plugin_utf8_buf_t password_cbuf;
						everything_plugin_utf8_buf_t include_only_path_cbuf;
						everything_plugin_utf8_buf_t include_only_mount_cbuf;
						int index;
						everything_server_remap_list_t remap_list;
						
						everything_plugin_utf8_buf_init(&name_cbuf);
						everything_plugin_utf8_buf_init(&password_cbuf);
						everything_plugin_utf8_buf_init(&include_only_path_cbuf);
						everything_plugin_utf8_buf_init(&include_only_mount_cbuf);
						everything_server_remap_list_init(&remap_list);
						
						everything_plugin_os_get_dlg_text(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_USER_NAME_EDIT,&name_cbuf);

						if (new_dialog->existing_user)
						{
							everything_plugin_utf8_buf_copy_utf8_string_n(&password_cbuf,new_dialog->existing_user->password,new_dialog->existing_user->password_len);
							
							everything_server_remap_list_get_path_list(&new_dialog->existing_user->remap_list,&include_only_path_cbuf);
							everything_server_remap_list_get_mount_list(&new_dialog->existing_user->remap_list,&include_only_mount_cbuf);
							
							everything_plugin_utf8_buf_copy_utf8_string_n(&password_cbuf,new_dialog->existing_user->password,new_dialog->existing_user->password_len);
							
							everything_server_user_list_remove(&new_dialog->options->user_list,new_dialog->existing_user);
						}
						
						index = everything_server_user_list_add(&new_dialog->options->user_list,name_cbuf.buf,name_cbuf.len,password_cbuf.buf,password_cbuf.len,include_only_path_cbuf.buf,include_only_mount_cbuf.buf,0);
						everything_server_update_options_page_user_list(new_dialog->page_hwnd,new_dialog->options,index);
						
						everything_server_enable_options_apply(new_dialog->options_hwnd,new_dialog->options);
												
						everything_server_remap_list_kill(&remap_list);
						everything_plugin_utf8_buf_kill(&include_only_mount_cbuf);
						everything_plugin_utf8_buf_kill(&include_only_path_cbuf);
						everything_plugin_utf8_buf_kill(&password_cbuf);
						everything_plugin_utf8_buf_kill(&name_cbuf);

						EndDialog(hwnd,1);
					}

					break;
				
				case IDCANCEL:

					EndDialog(hwnd,0);

					break;
			}
			
			break;
	}
	
	return 0;
}

// add a network_index, or edit an existing one
// set index to an existing network_index to edit, or -1 to add a new network_index.
static void everything_server_show_options_add_user_dialog(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options,everything_server_user_t *existing_user)
{
	everything_server_options_add_user_t new_dialog;
	
	everything_plugin_os_zero_memory(&new_dialog,sizeof(everything_server_options_add_user_t));
	
	new_dialog.options = options;
	new_dialog.options_hwnd = options_hwnd;
	new_dialog.page_hwnd = page_hwnd;
	new_dialog.existing_user = existing_user;
	
	// edit a new_dialog.
	everything_plugin_os_create_blank_dialog(options_hwnd,(const everything_plugin_utf8_t *)"",existing_user ? "Edit User" : "Add User",0,0,0,0,everything_server_options_add_user_dialog_proc,&new_dialog);
	
	if (new_dialog.tooltip_hwnd)
	{
		DestroyWindow(new_dialog.tooltip_hwnd);
	}
}

static void everything_server_user_free(everything_server_user_t *user)
{
	if (user->index_snapshot)
	{
		everything_server_index_snapshot_release(user->index_snapshot);
	}

	if (user->index_snapshot_expire_timer)
	{
		everything_plugin_timer_destroy(user->index_snapshot_expire_timer);
	}

	if (user->remap_array)	
	{
		everything_plugin_db_remap_array_destroy(user->remap_array);
	}
	
	everything_server_remap_list_kill(&user->remap_list);
	everything_plugin_mem_free(user->name);
	everything_plugin_mem_free(user->password);
	everything_plugin_mem_free(user);
}

static void everything_server_remap_free(everything_server_remap_t *remap)
{
	everything_plugin_mem_free(remap->mount);
	everything_plugin_mem_free(remap->path);
	everything_plugin_mem_free(remap);
}

static everything_server_user_t *everything_server_get_selected_user(HWND page_hwnd)
{
	return everything_server_user_from_index(page_hwnd,everything_plugin_os_get_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX));
}

static everything_server_remap_t *everything_server_get_selected_remap(HWND page_hwnd)
{
	return everything_server_remap_from_index(page_hwnd,everything_plugin_os_get_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX));
}

static void everything_server_remove_selected_user(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options)
{
	int index;
	
	index = everything_plugin_os_get_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_USER_LISTBOX);
	if (index >= 0)
	{
		everything_server_user_t *user;

		user = everything_server_user_from_index(page_hwnd,index);
		if (user)
		{
			everything_server_user_list_remove(&options->user_list,user);
			
			everything_server_update_options_page_user_list(page_hwnd,options,index);
			everything_server_enable_options_apply(options_hwnd,options);
		}
	}
}

static void everything_server_remove_selected_remap(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options)
{
	everything_server_user_t *user;
	
	user = everything_server_get_selected_user(page_hwnd);
	if (user)
	{
		int index;
		
		index = everything_plugin_os_get_listbox_cur_sel(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_REMAP_LISTBOX);
		if (index >= 0)
		{
			everything_server_remap_t *remap;

			remap = everything_server_remap_from_index(page_hwnd,index);
			if (remap)
			{
				everything_server_remap_list_remove(&user->remap_list,remap);
				
				everything_server_update_options_page_remap_list(page_hwnd,options,user,index);
				everything_server_enable_options_apply(options_hwnd,options);
			}
		}
	}
}

static void everything_server_edit_selected_user(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options)
{
	everything_server_show_options_add_user_dialog(options_hwnd,page_hwnd,options,everything_server_get_selected_user(page_hwnd));
}

static void everything_server_edit_selected_remap(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options)
{
	everything_server_show_options_add_remap_dialog(options_hwnd,page_hwnd,options,everything_server_get_selected_remap(page_hwnd));
}

static void everything_server_user_selection_changed(HWND page_hwnd,everything_server_options_t *options)
{
	everything_server_user_t *user;

	options->disallow_enable_apply++;

	user = everything_server_get_selected_user(page_hwnd);
	
	if (user)
	{
		everything_plugin_os_set_dlg_text(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,user->password);
	}
	else
	{
		everything_plugin_os_set_dlg_text(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,(const everything_plugin_utf8_t *)"");
	}

	everything_server_update_options_page_remap_list(page_hwnd,options,user,0);

	everything_server_update_options_page_buttons(page_hwnd);

	options->disallow_enable_apply--;
}

static void everything_server_remap_selection_changed(HWND page_hwnd,everything_server_options_t *options)
{
	everything_server_update_options_page_buttons(page_hwnd);
}

static void everything_server_user_setting_changed(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options)
{
	everything_server_user_t *user;

	user = everything_server_get_selected_user(page_hwnd);
	
	if (user)
	{
		everything_plugin_utf8_buf_t password_cbuf;

		everything_plugin_utf8_buf_init(&password_cbuf);

		everything_plugin_os_get_dlg_text(page_hwnd,EVERYTHING_SERVER_PLUGIN_ID_PASSWORD_EDIT,&password_cbuf);
		
		user->password_len = password_cbuf.len;
		user->password = everything_plugin_utf8_string_realloc_utf8_string(user->password,password_cbuf.buf);
		
		everything_plugin_utf8_buf_kill(&password_cbuf);
	}

	everything_server_enable_options_apply(options_hwnd,options);
}

static void everything_server_update_options_add_remap_buttons(HWND hwnd)
{
	everything_plugin_utf8_buf_t host_cbuf;
	
	everything_plugin_utf8_buf_init(&host_cbuf);
	
	everything_plugin_os_get_dlg_text(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT,&host_cbuf);

	everything_plugin_os_enable_or_disable_dlg_item(hwnd,IDOK,(host_cbuf.len) ? 1 : 0);

	everything_plugin_utf8_buf_kill(&host_cbuf);
}

static INT_PTR __stdcall everything_server_options_add_remap_dialog_proc(HWND hwnd,UINT msg,WPARAM wParam,LPARAM lParam)
{
	everything_server_options_add_remap_t *new_dialog;
	
	new_dialog = everything_plugin_os_get_window_user_data(hwnd);

	switch(msg)
	{
		case WM_INITDIALOG:
		{
			int x;
			int y;
			int wide;
			int high;
			const everything_plugin_utf8_t *include_only;
			const everything_plugin_utf8_t *mount;
			
			new_dialog = (everything_server_options_add_remap_t *)lParam;
			
			new_dialog->hwnd = hwnd;
			
			// save lparam			
			everything_plugin_os_set_window_user_data(hwnd,new_dialog);

			wide = 384;
			high = 98 + EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_STATIC_SEPARATOR + EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
		
			everything_plugin_os_center_dialog(GetParent(hwnd),hwnd,wide,high);
			
			x = 12;
			y = 12;
			wide -= 12*2;
			high -= 12*2;

			include_only =	(const everything_plugin_utf8_t *)"";
			mount = (const everything_plugin_utf8_t *)"";
		
			if (new_dialog->existing_remap)
			{	
				include_only = new_dialog->existing_remap->path;
				mount = new_dialog->existing_remap->mount;
			}

			// create a blank edit
			everything_plugin_os_create_static(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_STATIC,SS_LEFTNOWORDWRAP|WS_GROUP,"Path:");
			everything_plugin_os_set_dlg_rect(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_STATIC,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
			y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_STATIC_SEPARATOR;
			
			// create a blank edit
			everything_plugin_os_create_edit(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT,WS_GROUP,include_only);
			everything_plugin_os_set_dlg_rect(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH);
			everything_plugin_os_force_ltr_edit(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT);
			y += EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
			
				// create a blank edit
			everything_plugin_os_create_static(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_STATIC,SS_LEFTNOWORDWRAP,"Remap to:");
			everything_plugin_os_set_dlg_rect(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_STATIC,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH);
			y += EVERYTHING_PLUGIN_OS_DLG_STATIC_HIGH + EVERYTHING_PLUGIN_OS_DLG_STATIC_SEPARATOR;
			
			// create a blank edit
			everything_plugin_os_create_edit(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_EDIT,WS_GROUP,mount);
			everything_plugin_os_set_dlg_rect(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_EDIT,x,y,wide,EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH);
			everything_plugin_os_force_ltr_edit(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_EDIT);
			y += EVERYTHING_PLUGIN_OS_DLG_EDIT_HIGH + EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;
			
			y += EVERYTHING_PLUGIN_OS_DLG_SEPARATOR;

			// ok, cancel.
			everything_plugin_os_create_button(hwnd,IDOK,WS_GROUP,everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_OK));
			everything_plugin_os_set_dlg_rect(hwnd,IDOK,x + wide + 6 - ((75 + 6) * 2),y,75,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);
			everything_plugin_os_set_default_button(hwnd,IDOK);
			everything_plugin_os_create_button(hwnd,IDCANCEL,0,everything_plugin_localization_get_string(EVERYTHING_PLUGIN_LOCALIZATION_CANCEL));
			everything_plugin_os_set_dlg_rect(hwnd,IDCANCEL,x + wide + 6 - ((75 + 6) * 1),y,75,EVERYTHING_PLUGIN_OS_DLG_BUTTON_HIGH);

			if (everything_plugin_config_get_int_value("tooltips"))
			{
				// create tooltip window
				new_dialog->tooltip_hwnd = everything_plugin_os_create_tooltip();
				
				// setup help
				everything_plugin_os_add_tooltip(new_dialog->tooltip_hwnd,hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT,"The local path of the indexed folder to include.\nFor example: D:\\Media");
				everything_plugin_os_add_tooltip(new_dialog->tooltip_hwnd,hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_EDIT,"Remap the local path to this new remote location.\nFor example: \\\\Server\\Media\nLeave blank for no remapping.");
			}

			everything_server_update_options_add_remap_buttons(hwnd);

			// return true to focus the first dlg control.
			return TRUE;
		}
		
		case WM_COMMAND: 

			switch(LOWORD(wParam))
			{
				case EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT:
					
					if (HIWORD(wParam) == EN_CHANGE)
					{
						everything_server_update_options_add_remap_buttons(hwnd);
					}
				
					break;
				
				case IDOK:

					{
						everything_plugin_utf8_buf_t path_cbuf;
						everything_plugin_utf8_buf_t mount_cbuf;
						int index;
						
						everything_plugin_utf8_buf_init(&path_cbuf);
						everything_plugin_utf8_buf_init(&mount_cbuf);
						
						everything_plugin_os_get_dlg_text(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_PATH_EDIT,&path_cbuf);
						everything_plugin_os_get_dlg_text(hwnd,EVERYTHING_SERVER_PLUGIN_ID_ADD_REMAP_MOUNT_EDIT,&mount_cbuf);

						if (new_dialog->existing_remap)
						{
							everything_server_remap_list_remove(&new_dialog->user->remap_list,new_dialog->existing_remap);
						}
						
						index = everything_server_remap_list_add(&new_dialog->user->remap_list,path_cbuf.buf,mount_cbuf.buf,0);
						everything_server_update_options_page_remap_list(new_dialog->page_hwnd,new_dialog->options,new_dialog->user,index);
						
						everything_server_enable_options_apply(new_dialog->options_hwnd,new_dialog->options);
												
						everything_plugin_utf8_buf_kill(&mount_cbuf);
						everything_plugin_utf8_buf_kill(&path_cbuf);

						EndDialog(hwnd,1);
					}

					break;	
				
				case IDCANCEL:

					EndDialog(hwnd,0);

					break;
			}
			
			break;
	}
	
	return 0;
}

// add a network_index, or edit an existing one
// set index to an existing network_index to edit, or -1 to add a new network_index.
static void everything_server_show_options_add_remap_dialog(HWND options_hwnd,HWND page_hwnd,everything_server_options_t *options,everything_server_remap_t *existing_remap)
{
	everything_server_user_t *user;
	
	user = everything_server_get_selected_user(page_hwnd);

	if (user)
	{
		everything_server_options_add_remap_t new_dialog;
		
		everything_plugin_os_zero_memory(&new_dialog,sizeof(everything_server_options_add_remap_t));
		
		new_dialog.options = options;
		new_dialog.user = user;
		new_dialog.options_hwnd = options_hwnd;
		new_dialog.page_hwnd = page_hwnd;
		new_dialog.existing_remap = existing_remap;
		
		// edit a new_dialog.
		everything_plugin_os_create_blank_dialog(options_hwnd,(const everything_plugin_utf8_t *)"",existing_remap ? "Edit Include Only" : "Add Include Only",0,0,0,0,everything_server_options_add_remap_dialog_proc,&new_dialog);
		
		if (new_dialog.tooltip_hwnd)
		{
			DestroyWindow(new_dialog.tooltip_hwnd);
		}
	}
}

static void everything_server_user_list_init(everything_server_user_list_t *user_list)
{
	user_list->start = NULL;
	user_list->last = NULL;
}

static void everything_server_user_list_kill(everything_server_user_list_t *user_list)
{
	everything_server_user_t *user;
	
	user = user_list->start;

	while(user)
	{
		everything_server_user_t *next_user;
		
		next_user = user->next;
		
		everything_server_user_free(user);
		
		user = next_user;
	}
}

static int everything_server_user_list_add(everything_server_user_list_t *user_list,const everything_plugin_utf8_t *name,uintptr_t name_len,const everything_plugin_utf8_t *password,uintptr_t password_len,const everything_plugin_utf8_t *include_only_path_list,const everything_plugin_utf8_t *include_only_mount_list,int replace)
{
	int index;
	everything_server_user_t *user;
	everything_server_user_t *last_user;
	everything_server_user_t *new_user;
	
	index = 0;
	
	user = user_list->start;
	last_user = NULL;
	
	while(user)
	{
		int cmp;

		cmp = everything_plugin_utf8_string_icompare(user->name,name);
		
		if (cmp == 0)
		{
			everything_plugin_mem_free(user->name);
			
			user->name_len = name_len;
			user->name = everything_plugin_utf8_string_alloc_utf8_string_n(name,name_len);

			if (replace)
			{
				everything_plugin_mem_free(user->password);

				user->password_len = password_len;
				user->password = everything_plugin_utf8_string_alloc_utf8_string_n(password,password_len);
				
				everything_server_remap_list_load(&user->remap_list,include_only_path_list,include_only_mount_list);
			}
			
			return index;
		}

		if (cmp > 0)
		{
			break;	
		}
	
		last_user = user;
		user = user->next;
		index++;
	}
	
	// insert after last_user;
	new_user = everything_plugin_mem_alloc(sizeof(everything_server_user_t));
	
	new_user->index_snapshot = NULL;
	new_user->index_snapshot_expire_timer = NULL;
	new_user->remap_array = NULL;
	new_user->remap_id = 0;

	new_user->name_len = name_len;
	new_user->name = everything_plugin_utf8_string_alloc_utf8_string_n(name,name_len);
	new_user->password_len = password_len;
	new_user->password = everything_plugin_utf8_string_alloc_utf8_string_n(password,password_len);

	everything_server_remap_list_init(&new_user->remap_list);
	everything_server_remap_list_load(&new_user->remap_list,include_only_path_list,include_only_mount_list);
	
	if (last_user)
	{
		last_user->next = new_user;
	}
	else
	{
		user_list->start = new_user;
	}
	
	new_user->next = user;
	new_user->prev = last_user;
	
	if (user)
	{
		user->prev = new_user;
	}
	else
	{
		user_list->last = new_user;
	}

	return index;	
}

static void everything_server_user_list_remove(everything_server_user_list_t *user_list,everything_server_user_t *user)
{
	if (user_list->start == user)
	{
		user_list->start = user->next;
	}
	else
	{
		user->prev->next = user->next;
	}

	if (user_list->last == user)
	{
		user_list->last = user->prev;
	}
	else
	{
		user->next->prev = user->prev;
	}

	everything_server_user_free(user);
}

static void everything_server_user_list_empty(everything_server_user_list_t *user_list)
{
	everything_server_user_list_kill(user_list);
	everything_server_user_list_init(user_list);
}

static void everything_server_user_list_copy(everything_server_user_list_t *dst,const everything_server_user_list_t *src)
{
	everything_server_user_t *user;
	everything_plugin_utf8_buf_t include_only_path_cbuf;
	everything_plugin_utf8_buf_t include_only_mount_cbuf;

	everything_plugin_utf8_buf_init(&include_only_path_cbuf);
	everything_plugin_utf8_buf_init(&include_only_mount_cbuf);

	everything_server_user_list_empty(dst);
	
	user = src->start;
	while(user)
	{
		everything_server_remap_list_get_path_list(&user->remap_list,&include_only_path_cbuf);
		everything_server_remap_list_get_mount_list(&user->remap_list,&include_only_mount_cbuf);
	
		everything_server_user_list_add(dst,user->name,user->name_len,user->password,user->password_len,include_only_path_cbuf.buf,include_only_mount_cbuf.buf,1);
		
		user = user->next;
	}

	everything_plugin_utf8_buf_kill(&include_only_mount_cbuf);
	everything_plugin_utf8_buf_kill(&include_only_path_cbuf);
}

// name_list can be NULL.
static void everything_server_user_list_load(everything_server_user_list_t *user_list,const everything_plugin_utf8_t *name_list,const everything_plugin_utf8_t *password_list,const everything_plugin_utf8_t *include_only_path_list,const everything_plugin_utf8_t *include_only_mount_list)
{
	everything_server_user_list_empty(user_list);
	
	if (name_list)
	{
		everything_plugin_utf8_buf_t name_cbuf;
		everything_plugin_utf8_buf_t password_cbuf;
		everything_plugin_utf8_buf_t include_only_path_cbuf;
		everything_plugin_utf8_buf_t include_only_mount_cbuf;
		const everything_plugin_utf8_t *name_p;
		const everything_plugin_utf8_t *password_p;
		const everything_plugin_utf8_t *include_only_path_p;
		const everything_plugin_utf8_t *include_only_mount_p;

		everything_plugin_utf8_buf_init(&name_cbuf);
		everything_plugin_utf8_buf_init(&password_cbuf);
		everything_plugin_utf8_buf_init(&include_only_path_cbuf);
		everything_plugin_utf8_buf_init(&include_only_mount_cbuf);

		name_p = name_list;
		password_p = password_list;
		include_only_path_p = include_only_path_list;
		include_only_mount_p = include_only_mount_list;
		
		for(;;)
		{
			name_p = everything_plugin_utf8_string_parse_c_item(name_p,&name_cbuf);
			if (!name_p)
			{
				break;
			}
		
			password_p = everything_plugin_utf8_string_parse_c_item(password_p,&password_cbuf);
			include_only_path_p = everything_plugin_utf8_string_parse_c_item(include_only_path_p,&include_only_path_cbuf);
			include_only_mount_p = everything_plugin_utf8_string_parse_c_item(include_only_mount_p,&include_only_mount_cbuf);
			
			everything_server_user_list_add(&everything_server_user_list,name_cbuf.buf,name_cbuf.len,password_cbuf.buf,password_cbuf.len,include_only_path_cbuf.buf,include_only_mount_cbuf.buf,1);
		}

		everything_plugin_utf8_buf_kill(&include_only_mount_cbuf);
		everything_plugin_utf8_buf_kill(&include_only_path_cbuf);
		everything_plugin_utf8_buf_kill(&password_cbuf);
		everything_plugin_utf8_buf_kill(&name_cbuf);
	}
}

//////////////////////////////
// remap list
//////////////////////////////

static void everything_server_remap_list_init(everything_server_remap_list_t *remap_list)
{
	remap_list->start = NULL;
	remap_list->last = NULL;
}

static void everything_server_remap_list_kill(everything_server_remap_list_t *remap_list)
{
	everything_server_remap_t *remap;
	
	remap = remap_list->start;

	while(remap)
	{
		everything_server_remap_t *next_remap;
		
		next_remap = remap->next;
		
		everything_server_remap_free(remap);
		
		remap = next_remap;
	}
}

static int everything_server_remap_list_add(everything_server_remap_list_t *remap_list,const everything_plugin_utf8_t *path,const everything_plugin_utf8_t *mount,int replace)
{
	int index;
	everything_server_remap_t *remap;
	everything_server_remap_t *last_remap;
	everything_server_remap_t *new_remap;
	
	index = 0;
	
	remap = remap_list->start;
	last_remap = NULL;
	
	while(remap)
	{
		int cmp;

		cmp = everything_plugin_utf8_string_icompare(remap->path,path);
		
		if (cmp == 0)
		{
			everything_plugin_mem_free(remap->path);
			
			remap->path = everything_plugin_utf8_string_alloc_utf8_string(path);

			if (replace)
			{
				everything_plugin_mem_free(remap->mount);
				remap->mount = everything_plugin_utf8_string_alloc_utf8_string(mount);
			}
			
			return index;
		}

		if (cmp > 0)
		{
			break;	
		}
	
		last_remap = remap;
		remap = remap->next;
		index++;
	}
	
	// insert after last_remap;
	new_remap = everything_plugin_mem_alloc(sizeof(everything_server_remap_t));
	
	new_remap->path = everything_plugin_utf8_string_alloc_utf8_string(path);
	new_remap->mount = everything_plugin_utf8_string_alloc_utf8_string(mount);
	
	if (last_remap)
	{
		last_remap->next = new_remap;
	}
	else
	{
		remap_list->start = new_remap;
	}
	
	new_remap->next = remap;
	new_remap->prev = last_remap;
	
	if (remap)
	{
		remap->prev = new_remap;
	}
	else
	{
		remap_list->last = new_remap;
	}

	return index;	
}

static void everything_server_remap_list_remove(everything_server_remap_list_t *remap_list,everything_server_remap_t *remap)
{
	if (remap_list->start == remap)
	{
		remap_list->start = remap->next;
	}
	else
	{
		remap->prev->next = remap->next;
	}

	if (remap_list->last == remap)
	{
		remap_list->last = remap->prev;
	}
	else
	{
		remap->next->prev = remap->prev;
	}

	everything_server_remap_free(remap);
}

static void everything_server_remap_list_copy(everything_server_remap_list_t *dst,const everything_server_remap_list_t *src)
{
	everything_server_remap_t *remap;

	everything_server_remap_list_empty(dst);
	
	remap = src->start;
	while(remap)
	{
		everything_server_remap_list_add(dst,remap->path,remap->mount,1);
		
		remap = remap->next;
	}
}

static void everything_server_remap_list_empty(everything_server_remap_list_t *remap_list)
{
	everything_server_remap_list_kill(remap_list);
	everything_server_remap_list_init(remap_list);
}

// name_list can be NULL.
static void everything_server_remap_list_load(everything_server_remap_list_t *remap_list,const everything_plugin_utf8_t *path_list,const everything_plugin_utf8_t *mount_list)
{
	everything_server_remap_list_empty(remap_list);
	
	if (path_list)
	{
		everything_plugin_utf8_buf_t path_cbuf;
		everything_plugin_utf8_buf_t mount_cbuf;
		const everything_plugin_utf8_t *path_p;
		const everything_plugin_utf8_t *mount_p;

		everything_plugin_utf8_buf_init(&path_cbuf);
		everything_plugin_utf8_buf_init(&mount_cbuf);

		path_p = path_list;
		mount_p = mount_list;
		
		for(;;)
		{
			path_p = everything_plugin_utf8_string_parse_c_item(path_p,&path_cbuf);
			if (!path_p)
			{
				break;
			}
		
			mount_p = everything_plugin_utf8_string_parse_c_item(mount_p,&mount_cbuf);
			
			if (path_cbuf.len)
			{
				everything_server_remap_list_add(remap_list,path_cbuf.buf,mount_cbuf.buf,1);
			}
		}

		everything_plugin_utf8_buf_kill(&mount_cbuf);
		everything_plugin_utf8_buf_kill(&path_cbuf);
	}
}

static void everything_server_remap_list_get_path_list(everything_server_remap_list_t *remap_list,everything_plugin_utf8_buf_t *cbuf)
{
	everything_server_remap_t *remap;
	
	everything_plugin_utf8_buf_empty(cbuf);

	// path
	remap = remap_list->start;
	
	while(remap)
	{
		if (remap != remap_list->start)
		{
			everything_plugin_utf8_buf_cat_utf8_string(cbuf,";");
		}
		
		everything_plugin_utf8_buf_cat_c_list_utf8_string(cbuf,remap->path);

		remap = remap->next;
	}
}

static void everything_server_remap_list_get_mount_list(everything_server_remap_list_t *remap_list,everything_plugin_utf8_buf_t *cbuf)
{
	everything_server_remap_t *remap;
	
	everything_plugin_utf8_buf_empty(cbuf);

	// mount
	remap = remap_list->start;
	
	while(remap)
	{
		if (remap != remap_list->start)
		{
			everything_plugin_utf8_buf_cat_utf8_string(cbuf,";");
		}
		
		everything_plugin_utf8_buf_cat_c_list_utf8_string(cbuf,remap->mount);

		remap = remap->next;
	}
}

static int everything_server_user_list_is_equal(const everything_server_user_list_t *a,const everything_server_user_list_t *b)
{
	const everything_server_user_t *a_user;
	const everything_server_user_t *b_user;
	
	a_user = a->start;
	b_user = b->start;
	
	while(a_user)
	{
		if (!b_user)
		{
			return 0;
		}
		
		// same name?
		if (everything_plugin_utf8_string_compare(a_user->name,b_user->name) != 0)
		{
			return 0;
		}
	
		// same password?
		if (everything_plugin_utf8_string_compare(a_user->password,b_user->password) != 0)
		{
			return 0;
		}

		// same include only
		{
			everything_server_remap_t *a_remap;
			everything_server_remap_t *b_remap;
			
			a_remap = a_user->remap_list.start;
			b_remap = b_user->remap_list.start;
			
			while(a_remap)
			{
				if (!b_remap)
				{
					return 0;
				}
			
				// same path?
				if (everything_plugin_utf8_string_compare(a_remap->path,b_remap->path) != 0)
				{
					return 0;
				}
				
				// same mount?
				if (everything_plugin_utf8_string_compare(a_remap->mount,b_remap->mount) != 0)
				{
					return 0;
				}
				
				a_remap = a_remap->next;
				b_remap = b_remap->next;
			}
			
			if (b_remap)
			{
				return 0;
			}
		}
	
		a_user = a_user->next;
		b_user = b_user->next;
	}
	
	if (b_user)
	{
		return 0;
	}
	
	return 1;
}

static int everything_server_is_all_nuls(const BYTE *data,uintptr_t len)
{
	const BYTE *p;
	uintptr_t run;
	
	p = data;
	run = len;
	
	while(run)
	{
		if (*p)
		{
			return 0;
		}
		
		p++;
		run--;
	}
	
	return 1;
}
