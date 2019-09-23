
#include <stdio.h>
#include <sys/ioctl.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>

#include "xf86drm.h"
#include "xf86drmMode.h"

static const char dri_path[] = "/dev/dri/card0";

#define WS " \t\n"

enum {
	DEPTH = 24,
	BPP = 32,
};

struct drm_dev_t {
	uint32_t *buf;
	uint32_t conn_id, enc_id, crtc_id, fb_id;
	uint32_t width, height;
	uint32_t pitch, size, handle;
	drmModeModeInfo mode;
	drmModeCrtc *saved_crtc;
	struct drm_dev_t *next;
};

static int
eopen(const char *path, int flag)
{
	int fd;

	if ((fd = open(path, flag)) == -1) {
		err(EXIT_FAILURE, "cannot open `%s'", path);
	}
	return fd;
}

static void *
emmap(int addr, size_t len, int prot, int flag, int fd, off_t offset)
{
	void *fp;
	if ((fp = mmap(0, len, prot, flag, fd, offset)) == MAP_FAILED)
		err(EXIT_FAILURE, "mmap");
	return fp;
}

static int
drm_open(const char *path)
{
	int fd, flags;
	uint64_t has_dumb;

	fd = eopen(path, O_RDWR);

	if ((flags = fcntl(fd, F_GETFD)) == -1
		|| fcntl(fd, F_SETFD, flags | FD_CLOEXEC) == -1)
		err(EXIT_FAILURE, "fcntl FD_CLOEXEC failed");

	if (drmGetCap(fd, DRM_CAP_DUMB_BUFFER, &has_dumb) < 0 || has_dumb == 0)
		err(EXIT_FAILURE, "drmGetCap DRM_CAP_DUMB_BUFFER failed "
		    "or doesn't have dumb buffer");

	return fd;
}

static struct drm_dev_t *
drm_find_dev(int fd)
{
	int i;
	struct drm_dev_t *dev = NULL, *dev_head = NULL;
	drmModeRes *res;
	drmModeConnector *conn;
	drmModeEncoder *enc;

	if ((res = drmModeGetResources(fd)) == NULL)
		err(EXIT_FAILURE, "drmModeGetResources() failed");

	for (i = 0; i < res->count_connectors; i++) {
		conn = drmModeGetConnector(fd, res->connectors[i]);

		if (conn == NULL)
			continue;
		if (conn->connection != DRM_MODE_CONNECTED
		    || conn->count_modes <= 0) {
			drmModeFreeConnector(conn);
			continue;
		}
		dev = calloc(1, sizeof(*dev));

		dev->conn_id = conn->connector_id;
		dev->enc_id = conn->encoder_id;
		dev->next = NULL;

		memcpy(&dev->mode, &conn->modes[0], sizeof(dev->mode));
		dev->width = conn->modes[0].hdisplay;
		dev->height = conn->modes[0].vdisplay;

		if ((enc = drmModeGetEncoder(fd, dev->enc_id)) == NULL)
			err(EXIT_FAILURE, "drmModeGetEncoder() faild");
		dev->crtc_id = enc->crtc_id;
		drmModeFreeEncoder(enc);

		dev->saved_crtc = NULL;

		dev->next = dev_head;
		dev_head = dev;
		drmModeFreeConnector(conn);
	}
	drmModeFreeResources(res);

	return dev_head;
}

static void
drm_setup_fb(int fd, struct drm_dev_t *dev)
{
	struct drm_mode_create_dumb creq;
	struct drm_mode_map_dumb mreq;

	memset(&creq, 0, sizeof(creq));
	creq.width = dev->width;
	creq.height = dev->height;
	creq.bpp = BPP; 

	if (drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &creq) == -1) {
		err(EXIT_FAILURE, "drmIoctl DRM_IOCTL_MODE_CREATE_DUMB failed");
	}

	dev->pitch = creq.pitch;
	dev->size = (uint32_t) creq.size;
	dev->handle = creq.handle;

	if (drmModeAddFB(fd, dev->width, dev->height,
	    DEPTH, BPP, dev->pitch, dev->handle, &dev->fb_id)){
		err(EXIT_FAILURE, "drmModeAddFB failed");
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.handle = dev->handle;

	if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &mreq) == -1) {
		err(EXIT_FAILURE, "drmIoctl DRM_IOCTL_MODE_MAP_DUMB failed");
	}

	dev->buf = emmap(0, dev->size, PROT_READ | PROT_WRITE, MAP_SHARED,
	    fd, (off_t)mreq.offset);

	dev->saved_crtc = drmModeGetCrtc(fd, dev->crtc_id); 
	if (drmModeSetCrtc(fd, dev->crtc_id, dev->fb_id, 0, 0, &dev->conn_id,
	    1, &dev->mode)) {
		err(EXIT_FAILURE, "drmModeSetCrtc() failed");
	}
}

static void
drm_destroy(int fd, struct drm_dev_t *dev_head)
{
	struct drm_dev_t *devp, *devp_tmp;
	struct drm_mode_destroy_dumb dreq;

	for (devp = dev_head; devp != NULL;) {
		if (devp->saved_crtc) {
			drmModeSetCrtc(fd, devp->saved_crtc->crtc_id,
			    devp->saved_crtc->buffer_id, devp->saved_crtc->x,
			    devp->saved_crtc->y, &devp->conn_id, 1,
			    &devp->saved_crtc->mode);
		}
		drmModeFreeCrtc(devp->saved_crtc);

		munmap(devp->buf, devp->size);

		drmModeRmFB(fd, devp->fb_id);

		memset(&dreq, 0, sizeof(dreq));
		dreq.handle = devp->handle;
		drmIoctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &dreq);

		devp_tmp = devp;
		devp = devp->next;
		free(devp_tmp);
	}

	close(fd);
}

static void
drm_ioctl_version(int fd)
{
	struct drm_version vers;

	if (ioctl(fd, DRM_IOCTL_VERSION, &vers) == -1)
		warn("DRM_IOCTL_VERSION");

	printf("DRM_IOCTL_VERSION: version_major: %d, "
	    "version_minor: %d, "
	    "version_patchlevel: %d, "
	    "name_len: %zu\n",
	    vers.version_major,
	    vers.version_minor,
	    vers.version_patchlevel,
	    vers.name_len);
}

static void
drm_ioctl_get_unique(int fd)
{
	struct drm_unique unique;
	if (ioctl(fd, DRM_IOCTL_GET_UNIQUE, &unique) == -1)
		warn("DRM_IOCTL_GET_UNIQUE");
	
	printf("DRM_IOCTL_GET_UNIQUE: unique_len: %zu, "
	    "unique: %s\n", unique.unique_len, unique.unique);
}

static void
drm_ioctl_set_unique(int fd)
{
	struct drm_unique unique;

	memset(&unique, 0, sizeof(unique));

	const char *len = strtok(NULL, WS);
	if (len == NULL) {
		warnx("set_unique: Missing length\n");
		return;
	}

	const char *ptr = strtok(NULL, WS);
	if (ptr == NULL) {
		warnx("set_unique: Missing unique\n");
		return;
	}

	unique.unique_len = strtoul(len, NULL, 0);
	if (unique.unique_len >= sizeof(unique.unique)) {
		warnx("set_unique: bad length %zu\n", unique.unique_len);
		return;
	}
	memcpy(unique.unique, ptr, unique.unique_len);

	if (ioctl(fd, DRM_IOCTL_SET_UNIQUE, &unique) == -1)
		warn("DRM_IOCTL_SET_UNIQUE");

	printf("DRM_IOCTL_SET_UNIQUE: unique_len: %zu, unique: %s\n",
	    unique.unique_len, unique.unique);
}

// XXX: Fixed up to there.
static void
drm_ioctl_get_map(int fd){
	struct drm_map map;
	if (ioctl(fd, DRM_IOCTL_GET_MAP, &map) == -1)
		warn("error");
	
	printf("offset:%ld,size:%ld,mtrr:%d", map.offset, map.size, map.mtrr);
	printf("Struct members: offset,size:,type,map_flag,handle,mtrr\n");
}

static void
drm_ioctl_add_map(int fd){
	struct drm_map map;
	if (ioctl(fd, DRM_IOCTL_ADD_MAP, &map) == -1)
		warn("error");
	
	printf("offset:%ld,size:%ld,map_type:%d,map_flag%d,handle:%p,mtrr:%d", map.offset, map.size, map.type, map.flags, map.handle, map.mtrr);
	printf("Struct members: offset,size,map_type,map_flag,handle,mtrr\n");
}

static void
drm_ioctl_rm_map(int fd){
	struct drm_map map;
	if (ioctl(fd, DRM_IOCTL_RM_MAP, &map) == -1)
		warn("error");

	printf("offset:%ld,size:%ld,map_type:%d,map_flag%d,handle:%p,mtrr:%d", map.offset, map.size, map.type, map.flags, map.handle, map.mtrr);
	printf("Struct members: offset,size,map_type,map_flag,handle,mtrr\n");
}

static void
drm_ioctl_get_client(int fd){
	struct drm_client client;
	if (ioctl(fd, DRM_IOCTL_GET_CLIENT, &client) == -1)
		warn("error");

	printf("idx:%d,auth:%d,pid:%ld,uid:%ld,magic:%ld,iocs:%ld", client.idx, client.auth, client.pid, client.uid, client.magic, client.iocs);
	printf("Struct members: idx,auth,pid,uid,magic,iocs\n");
}

static void
drm_ioctl_get_stats(int fd){
	struct drm_stats stats;
	if (ioctl(fd, DRM_IOCTL_GET_STATS, &stats) == -1)
		warn("error");
	
	printf("count:%ld",stats.count);
	printf("Struct members: count\n");
}

static void
drm_ioctl_add_bufs(int fd){
	struct drm_buf_desc desc;

	if (ioctl(fd, DRM_IOCTL_ADD_BUFS, &desc) == -1)
		warn("error");

	printf("count:%d,size:%d,low_mark:%d,high_mark:%d,flags:%d,agp_start:%ld", desc.count, desc.size, desc.low_mark, desc.high_mark, desc.flags, desc.agp_start);
	printf("Struct members: count,size,low_mark,high_mark,flags,agp_start\n");
}

static void
drm_ioctl_mark_bufs(int fd){
	struct drm_buf_desc desc;
	if (ioctl(fd, DRM_IOCTL_MARK_BUFS, &desc) == -1)
		warn ("error");

	printf("count:%d,size:%d,low_mark:%d,high_mark:%d,flags:%d,agp_start:%ld", desc.count, desc.size, desc.low_mark, desc.high_mark, desc.flags, desc.agp_start);
	printf("Struct members: count,size,low_mark,high_mark,flags,agp_start\n");
}

static void
drm_ioctl_free_bufs(int fd){
	struct drm_buf_desc desc;
	if (ioctl(fd, DRM_IOCTL_FREE_BUFS, &desc) == -1)
		warn("error");

	printf("count:%d,size:%d,low_mark:%d,high_mark:%d,flags:%d,agp_start:%ld", desc.count, desc.size, desc.low_mark, desc.high_mark, desc.flags, desc.agp_start);
	printf("Struct members: count,size,low_mark,high_mark,flags,agp_start\n");
}

static void
drm_ioctl_set_sarea_ctx(int fd){
	struct drm_ctx_priv_map sarea;

	if (ioctl(fd, DRM_IOCTL_SET_SAREA_CTX, &sarea) == -1)
		warn("error");
	
	printf("ctx_id:%d,handle:%p", sarea.ctx_id,sarea.handle);
	printf("Struct members: ctx_id,handle\n");
}

static void
drm_ioctl_get_sarea_ctx(int fd){
	struct drm_ctx_priv_map sarea;

	if (ioctl(fd, DRM_IOCTL_GET_SAREA_CTX, &sarea) == -1)
		warn("error");
		
	printf("ctx_id:%d,handle:%p", sarea.ctx_id,sarea.handle);
	printf("Struct members: ctx_id,handle\n");
}

static void
drm_ioctl_res_ctx(int fd){
	struct drm_ctx_res res;
	if (ioctl(fd, DRM_IOCTL_RES_CTX, &res) == -1)
		warn("error");

	printf("count:%d", res.count);
	printf("Struct members: count\n");
}

static void
drm_ioctl_dma(int fd){
	struct drm_dma dma;
	if (ioctl(fd, DRM_IOCTL_DMA, &dma) == -1)
		warn("error");
		
	printf("context:%d", dma.context);
	printf("Struct members: context\n");
}

static void
drm_ioctl_agp_enable(int fd){
	struct drm_agp_mode agp;
	if (ioctl(fd, DRM_IOCTL_AGP_ENABLE, &agp) == -1)
		warn("error");

	printf("mode:%ld",agp.mode);
	printf("Struct members: mode\n");
}

static void
drm_ioctl_agp_info(int fd){
	struct drm_agp_info agp_info;
	if (ioctl(fd, DRM_IOCTL_AGP_INFO, &agp_info) == -1)
		warn("error");

	printf("agp_version_major:%d", agp_info.agp_version_major);
	printf("Struct members: agp_version_major\n");
}

static void
drm_ioctl_agp_alloc(int fd){
	struct drm_agp_buffer agp_buffer;
	if (ioctl(fd, DRM_IOCTL_AGP_ALLOC, &agp_buffer) == -1)
		warn("error");

	printf("agp_buffer_size:%ld, agp_buffer_handle:%ld, agp_buffer_type:%ld, agp_buffer_physical:%ld ", agp_buffer.size, agp_buffer.handle, agp_buffer.type, agp_buffer.physical);
	printf("Struct membersagp_buffer_size, agp_buffer_handle, agp_buffer_type, agp_buffer_physical\n");
}

static void
drm_ioctl_agp_free(int fd){
	struct drm_agp_buffer agp_buffer;
	if (ioctl(fd, DRM_IOCTL_AGP_FREE, &agp_buffer) == -1)
		warn("error");

	printf("agp_buffer_size:%ld, agp_buffer_handle:%ld, agp_buffer_type:%ld, agp_buffer_physical:%ld ", agp_buffer.size, agp_buffer.handle, agp_buffer.type, agp_buffer.physical);
	printf("Struct members: agp_buffer_size, agp_buffer_handle, agp_buffer_type, agp_buffer_physical\n");
}

static void
drm_ioctl_agp_bind(int fd){
	struct drm_agp_binding agp_bind;
	if (ioctl(fd, DRM_IOCTL_AGP_BIND, &agp_bind) == -1)
		warn("error");

	printf("agp_bind_handle:%ld, agp_bind_offset:%ld", agp_bind.handle, agp_bind.offset);
	printf("Struct members: agp_bind_handle, agp_bind_offset\n");
}

static void
drm_ioctl_agp_unbind(int fd){
	struct drm_agp_binding agp_unbind;
	if (ioctl(fd, DRM_IOCTL_AGP_UNBIND, &agp_unbind) == -1)
		warn("error");

	printf("agp_unbind_handle:%ld, agp_unbind_offset:%ld", agp_unbind.handle, agp_unbind.offset);
	printf("Struct members: agp_bind_handle, agp_bind_offset\n");
}

static void
drm_ioctl_sg_alloc(int fd){
	struct drm_scatter_gather sg;
	if (ioctl(fd, DRM_IOCTL_SG_ALLOC, &sg) == -1)
		warn("error");

	printf("sg_size:%ld, sg_handle:%ld", sg.size, sg.handle);
	printf("Struct members: sg_size, sg_handle");
}

static void
drm_ioctl_sg_free(int fd){
	struct drm_scatter_gather sg;
	if (ioctl(fd, DRM_IOCTL_SG_FREE, &sg) == -1)
		warn("error");

	printf("sg_size:%ld, sg_handle:%ld", sg.size, sg.handle);
	printf("Struct members: sg_size, sg_handle");
}

static void
drm_ioctl_update_draw(int fd){
	struct drm_update_draw update_draw;
	if (ioctl(fd, DRM_IOCTL_UPDATE_DRAW, &update_draw) == -1)
		warn("error");

	printf("update_draw_type:%d, update_draw_num:%d, update_draw_data:%lld", update_draw.type, update_draw.num, update_draw.data);
	printf("Struct members: update_draw_type, update_draw_num, update_draw_data\n");

}

static void
drm_ioctl_wait_vblank(int fd){
	union drm_wait_vblank vblank;
	if (ioctl(fd, DRM_IOCTL_WAIT_VBLANK, &vblank) == -1)
		warn("error");

	printf("vblank_request_sequence:%d, vblank_request_signal:%ld, vblank_reply_sequence:%d", vblank.request.sequence, vblank.request.signal, vblank.reply.sequence);
	printf("Struct members: vblank_request_sequence, vblank_request_signal, vblank_reply_sequence");
}

static void
drm_ioctl_addfb2(int fd){
	struct drm_mode_fb_cmd2 addfb2;
	if (ioctl(fd, DRM_IOCTL_MODE_ADDFB2, &addfb2) == -1)
		warn("error");

	printf("fb_id:%d, width:%d, height:%d, pixel_format:%d, flags:%d", addfb2.fb_id, addfb2.width, addfb2.height, addfb2.pixel_format, addfb2.flags);
#ifdef notyet
	for(int i = 0; i < 4; i++)
	       printf("handles:%d, pitches:%d, offsets:%d, modifiers:%lld", addfb2.handles[i], addfb2.pitches[i], addfb2.offsets[i], addfb2.modifier[i]);
	printf("Struct members: fb_id, width, height, pixel_format, flags, handles, pitches, offsets, modifiers");	
#endif
}

static struct {
	const char* name;
	void (*func)(int);
} cmd[] = {
	{ "version",		drm_ioctl_version },
	{ "get_unique",		drm_ioctl_get_unique },
	{ "set_unique",		drm_ioctl_set_unique },
	{ "get_map",		drm_ioctl_get_map },
	{ "add_map",		drm_ioctl_add_map },
	{ "rm_map",		drm_ioctl_rm_map },
	{ "get_client",		drm_ioctl_get_client },
	{ "get_stats",		drm_ioctl_get_stats },
	{ "add_bufs",		drm_ioctl_add_bufs },
	{ "mark_bufs",		drm_ioctl_mark_bufs },
	{ "free_bufs",		drm_ioctl_free_bufs },
	{ "set_sarea",		drm_ioctl_set_sarea_ctx },
	{ "get_sarea",		drm_ioctl_get_sarea_ctx },
	{ "res_ctx",		drm_ioctl_res_ctx },
	{ "dma",		drm_ioctl_dma },
	{ "agp_enable",		drm_ioctl_agp_enable },
	{ "agp_info",		drm_ioctl_agp_info },
	{ "agp_alloc",		drm_ioctl_agp_alloc },
	{ "agp_free",		drm_ioctl_agp_free },
	{ "agp_bind",		drm_ioctl_agp_bind },
	{ "agp_unbind",		drm_ioctl_agp_unbind },
	{ "sg_alloc",		drm_ioctl_sg_alloc },
	{ "sg_free",		drm_ioctl_sg_free },
	{ "update_draw",	drm_ioctl_update_draw },
	{ "wait_vblank",	drm_ioctl_wait_vblank },
	{ "mode_addfb2",	drm_ioctl_addfb2 }
};

int main(void)
{
	int fd;
	struct drm_dev_t *dev_head, *dev;

	fd = drm_open(dri_path);
	dev_head = drm_find_dev(fd);

	if (dev_head == NULL) {
		err(EXIT_FAILURE, "Available drm_dev not found\n");
	}

	dev = dev_head;
	drm_setup_fb(fd, dev);

	char line[1024];
	for (;;) {
		printf("Enter the operation to perform:");
		if (fgets(line, sizeof(line), stdin) == NULL)
			break;

		char *name = strtok(line, WS);
		if (name == NULL)
			continue;

		size_t i;
		for (i = 0; i < __arraycount(cmd);i++) {
			if (strcmp(cmd[i].name, name) == 0) {
				(*cmd[i].func)(fd);
				break;
			}
		}
		if (i == __arraycount(cmd)) {
			warnx("unknown cmd %s", name);
			continue;
		}
	}

	drm_destroy(fd, dev_head);
	return EXIT_SUCCESS;
}
