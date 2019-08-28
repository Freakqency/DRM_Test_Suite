#define _XOPEN_SOURCE 600

#include <stdio.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include "xf86drm.h"
#include "xf86drmMode.h"

static const char *dri_path = "/dev/dri/card0";

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

void fatal(char *str)
{
	fprintf(stderr, "%s\n", str);
	exit(EXIT_FAILURE);
}

void error(char *str)
{
	perror(str);
	exit(EXIT_FAILURE);
}

int eopen(const char *path, int flag)
{
	int fd;

	if ((fd = open(path, flag)) < 0) {
		fprintf(stderr, "cannot open \"%s\"\n", path);
		error("open");
	}
	return fd;
}

void *emmap(int addr, size_t len, int prot, int flag, int fd, off_t offset)
{
	uint32_t *fp;

	if ((fp = (uint32_t *) mmap(0, len, prot, flag, fd, offset)) == MAP_FAILED)
		error("mmap");
	return fp;
}

int drm_open(const char *path)
{
	int fd, flags;
	uint64_t has_dumb;

	fd = eopen(path, O_RDWR);

	if ((flags = fcntl(fd, F_GETFD)) < 0
		|| fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
		fatal("fcntl FD_CLOEXEC failed");

	if (drmGetCap(fd, DRM_CAP_DUMB_BUFFER, &has_dumb) < 0 || has_dumb == 0)
		fatal("drmGetCap DRM_CAP_DUMB_BUFFER failed or doesn't have dumb buffer");

	return fd;
}

struct drm_dev_t *drm_find_dev(int fd)
{
	int i;
	struct drm_dev_t *dev = NULL, *dev_head = NULL;
	drmModeRes *res;
	drmModeConnector *conn;
	drmModeEncoder *enc;

	if ((res = drmModeGetResources(fd)) == NULL)
		fatal("drmModeGetResources() failed");

	for (i = 0; i < res->count_connectors; i++) {
		conn = drmModeGetConnector(fd, res->connectors[i]);

		if (conn != NULL && conn->connection == DRM_MODE_CONNECTED && conn->count_modes > 0) {
			dev = (struct drm_dev_t *) malloc(sizeof(struct drm_dev_t));
			memset(dev, 0, sizeof(*dev));

			dev->conn_id = conn->connector_id;
			dev->enc_id = conn->encoder_id;
			dev->next = NULL;

			memcpy(&dev->mode, &conn->modes[0], sizeof(drmModeModeInfo));
			dev->width = conn->modes[0].hdisplay;
			dev->height = conn->modes[0].vdisplay;

			if ((enc = drmModeGetEncoder(fd, dev->enc_id)) == NULL)
				fatal("drmModeGetEncoder() faild");
			dev->crtc_id = enc->crtc_id;
			drmModeFreeEncoder(enc);

			dev->saved_crtc = NULL;

			dev->next = dev_head;
			dev_head = dev;
		}
		drmModeFreeConnector(conn);
	}
	drmModeFreeResources(res);

	return dev_head;
}

int drm_setup_fb(int fd, struct drm_dev_t *dev)
{
	struct drm_mode_create_dumb creq;
	struct drm_mode_map_dumb mreq;

	memset(&creq, 0, sizeof(creq));
	creq.width = dev->width;
	creq.height = dev->height;
	creq.bpp = BPP; 

	if (drmIoctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &creq) < 0){
		fatal("drmIoctl DRM_IOCTL_MODE_CREATE_DUMB failed");
		return 1;
	}

	dev->pitch = creq.pitch;
	dev->size = creq.size;
	dev->handle = creq.handle;

	if (drmModeAddFB(fd, dev->width, dev->height,
		DEPTH, BPP, dev->pitch, dev->handle, &dev->fb_id)){
		fatal("drmModeAddFB failed");
		return 1;
	}

	memset(&mreq, 0, sizeof(mreq));
	mreq.handle = dev->handle;

	if (drmIoctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &mreq)){
		fatal("drmIoctl DRM_IOCTL_MODE_MAP_DUMB failed");
		return 1;
	}

	dev->buf = (uint32_t *) emmap(0, dev->size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, mreq.offset);

	dev->saved_crtc = drmModeGetCrtc(fd, dev->crtc_id); 
	if (drmModeSetCrtc(fd, dev->crtc_id, dev->fb_id, 0, 0, &dev->conn_id, 1, &dev->mode)){
		fatal("drmModeSetCrtc() failed");
		return 1;
	}

	return 0;
}

int drm_destroy(int fd, struct drm_dev_t *dev_head)
{
	struct drm_dev_t *devp, *devp_tmp;
	struct drm_mode_destroy_dumb dreq;

	for (devp = dev_head; devp != NULL;) {
		if (devp->saved_crtc)
			drmModeSetCrtc(fd, devp->saved_crtc->crtc_id, devp->saved_crtc->buffer_id,
				devp->saved_crtc->x, devp->saved_crtc->y, &devp->conn_id, 1, &devp->saved_crtc->mode);
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
	return 0;
}

void drm_ioctl_version(int fd){
	struct drm_version vers;

	if (!ioctl(fd, DRM_IOCTL_VERSION, &vers))
		warn("Version_major:%d,Version_minor:%d,Version_patchlevel:%d,Name_len:%d,\n",vers.version_major, vers.version_minor, vers.version_patchlevel,vers.name_len);
	else
		warn("drm_ioctl_version");

	printf("Struct Members :Version_major, Version_minor, Patchlevel, Name_len, Date_len, Desc_len\n");
}

void drm_ioctl_get_unique(int fd){
	struct drm_unique unique;
	if (!ioctl(fd, DRM_IOCTL_GET_UNIQUE, &unique))
		warn("unique_len:%d,unique:%s",unique.unique_len, unique.unique);
	else
		warn("error");
	
	printf("Struct members Unique_len,unique\n");
}

void drm_ioctl_set_unique(int fd){
	struct drm_unique unique;
	if (!ioctl(fd, DRM_IOCTL_SET_UNIQUE, &unique))
		warn("unique_len:%d,unique:%s",unique.unique_len, unique.unique);
	else
		warn("error");

	printf("Struct members: Unique_len,unique\n");
}

void drm_ioctl_get_map(int fd){
	struct drm_map map;
	if (!ioctl(fd, DRM_IOCTL_GET_MAP, &map))
		warn("offset:%ld,size:%ld,mtrr:%d",map.offset,map.size,map.mtrr);
	else
		warn("error");
	
	printf("Struct members: offset,size:,type,map_flag,handle,mtrr\n");
}

void drm_ioctl_add_map(int fd){
	struct drm_map map;
	if (!ioctl(fd, DRM_IOCTL_ADD_MAP, &map))
		warn("offset:%ld,size:%ld,map_type:%d,map_flag%d,handle:%p,mtrr:%d",map.offset,map.size,map.type,map.flags,map.handle,map.mtrr);

	else
		warn("error");
	
	printf("Struct members: offset,size,map_type,map_flag,handle,mtrr\n");
}

void drm_ioctl_rm_map(int fd){
	struct drm_map map;
	if (!ioctl(fd, DRM_IOCTL_RM_MAP, &map))
		warn("offset:%ld,size:%ld,map_type:%d,map_flag%d,handle:%p,mtrr:%d",map.offset,map.size,map.type,map.flags,map.handle,map.mtrr);
	else
		warn("error");

	printf("Struct members: offset,size,map_type,map_flag,handle,mtrr\n");
}

void drm_ioctl_get_client(int fd){
	struct drm_client client;
	if (!ioctl(fd, DRM_IOCTL_GET_CLIENT, &client))
		warn("idx:%d,auth:%d,pid:%ld,uid:%ld,magic:%ld,iocs:%ld",client.idx,client.auth,client.pid,client.uid,client.magic,client.iocs);
	else
		warn("error");

	printf("Struct members: idx,auth,pid,uid,magic,iocs\n");
}

void drm_ioctl_get_stats(int fd){
	struct drm_stats stats;
	if (!ioctl(fd, DRM_IOCTL_GET_STATS, &stats))
		warn("count:%ld",stats.count);
	else
		warn("error");
	
	printf("Struct members: count\n");
}

void drm_ioctl_add_bufs(int fd){
	struct drm_buf_desc desc;

	if (!ioctl(fd, DRM_IOCTL_ADD_BUFS, &desc))
		warn("count:%d,size:%d,low_mark:%d,high_mark:%d,flags:%d,agp_start:%ld",desc.count,desc.size,desc.low_mark,desc.high_mark,desc.flags,desc.agp_start);
	else
		warn("error");

	printf("Struct members: count,size,low_mark,high_mark,flags,agp_start\n");
}

void drm_ioctl_mark_bufs(int fd){
	struct drm_buf_desc desc;
	if (!ioctl(fd, DRM_IOCTL_MARK_BUFS, &desc))
		warn("count:%d,size:%d,low_mark:%d,high_mark:%d,flags:%d,agp_start:%ld",desc.count,desc.size,desc.low_mark,desc.high_mark,desc.flags,desc.agp_start);
	else
		warn ("error");

	printf("Struct members: count,size,low_mark,high_mark,flags,agp_start\n");
}

void drm_ioctl_free_bufs(int fd){
	struct drm_buf_desc desc;
	if (!ioctl(fd, DRM_IOCTL_FREE_BUFS, &desc))
		warn("count:%d,size:%d,low_mark:%d,high_mark:%d,flags:%d,agp_start:%ld",desc.count,desc.size,desc.low_mark,desc.high_mark,desc.flags,desc.agp_start);
	else
		warn("error");

	printf("Struct members: count,size,low_mark,high_mark,flags,agp_start\n");
}

void drm_ioctl_set_sarea_ctx(int fd){
	struct drm_ctx_priv_map sarea;

	if (!ioctl(fd, DRM_IOCTL_SET_SAREA_CTX, &sarea))
		warn("ctx_id:%d,handle:%p",sarea.ctx_id,sarea.handle);
	else
		warn("error");
	
	printf("Struct members: ctx_id,handle\n");
}

void drm_ioctl_get_sarea_ctx(int fd){
	struct drm_ctx_priv_map sarea;

	if (!ioctl(fd, DRM_IOCTL_GET_SAREA_CTX, &sarea))
		warn("ctx_id:%d,handle:%p",sarea.ctx_id,sarea.handle);
	else
		warn("error");
		
	printf("Struct members: ctx_id,handle\n");
}

void drm_ioctl_res_ctx(int fd){
	struct drm_ctx_res res;
	if (!ioctl(fd, DRM_IOCTL_RES_CTX, &res))
		warn("count:%d",res.count);
	else
		warn("error");

	printf("Struct members: count\n");
}

void drm_ioctl_dma(int fd){
	struct drm_dma dma;
	if (!ioctl(fd, DRM_IOCTL_DMA, &dma))
		warn("context:%d",dma.context);
	else
		warn("error");
		
	printf("Struct members: context\n");
}

void drm_ioctl_agp_enable(int fd){
	struct drm_agp_mode agp;
	if (!ioctl(fd, DRM_IOCTL_AGP_ENABLE, &agp))
		printf("mode:%ld",agp.mode);
	else
		warn("error");

	printf("Struct members: mode\n");
}

void drm_ioctl_agp_info(int fd){
	struct drm_agp_info agp_info;
	if (!ioctl(fd, DRM_IOCTL_AGP_INFO, &agp_info))
		warn("agp_version_major:%d",agp_info.agp_version_major);
	else
		warn("error");

	printf("Struct members: agp_version_major\n");
}

struct {
	const char* name;
	void (*func)(int);
}cmd[] = {
	{"version", drm_ioctl_version},
	{"get_unique", drm_ioctl_get_unique},
	{"set_unique", drm_ioctl_set_unique},
	{"get_map", drm_ioctl_get_map},
	{"add_map", drm_ioctl_add_map},
	{"rm_map", drm_ioctl_rm_map},
	{"get_client", drm_ioctl_get_client},
	{"get_stats", drm_ioctl_get_stats},
	{"add_bufs", drm_ioctl_add_bufs},
	{"mark_bufs", drm_ioctl_mark_bufs},
	{"free_bufs", drm_ioctl_free_bufs},
	{"set_sarea", drm_ioctl_set_sarea_ctx},
	{"get_sarea", drm_ioctl_get_sarea_ctx},
	{"res_ctx", drm_ioctl_res_ctx},
	{"dma", drm_ioctl_dma},
	{"agp_enable", drm_ioctl_agp_enable},
	{"agp_info", drm_ioctl_agp_info}


};

int main()
{
	int fd;
	struct drm_dev_t *dev_head, *dev;

	fd = drm_open(dri_path);
	dev_head = drm_find_dev(fd);

	if (dev_head == NULL) {
		fprintf(stderr, "available drm_dev not found\n");
		return EXIT_FAILURE;
	}

	dev = dev_head;
	drm_setup_fb(fd, dev);

	char name[100];
	printf("Enter the operation to perform:");
	scanf("%s", name);

	size_t i;
	for (i = 0;i < __arraycount(cmd);i++){
		if (strcmp(cmd[i].name,name) == 0){
			(*cmd[i].func)(fd);
			break;
		}
	}
	if (i == __arraycount(cmd))
	       warn("unknown cmd %s",name);

	sleep(3);
	drm_destroy(fd, dev_head);
	return 0;
}
