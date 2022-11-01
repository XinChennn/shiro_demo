/*
 Navicat Premium Data Transfer

 Source Server         : company
 Source Server Type    : MySQL
 Source Server Version : 80030 (8.0.30)
 Source Host           : localhost:3306
 Source Schema         : ginhello

 Target Server Type    : MySQL
 Target Server Version : 80030 (8.0.30)
 File Encoding         : 65001

 Date: 01/11/2022 13:35:51
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for user_role
-- ----------------------------
DROP TABLE IF EXISTS `user_role`;
CREATE TABLE `user_role`  (
  `id` int NOT NULL AUTO_INCREMENT COMMENT '用户-权限表id',
  `role_id` int NULL DEFAULT NULL COMMENT '权限id',
  `user_id` int NULL DEFAULT NULL COMMENT '用户id',
  PRIMARY KEY (`id`) USING BTREE
) ENGINE = InnoDB AUTO_INCREMENT = 5 CHARACTER SET = utf8mb4 COLLATE = utf8mb4_bin ROW_FORMAT = Dynamic;

-- ----------------------------
-- Records of user_role
-- ----------------------------
INSERT INTO `user_role` VALUES (1, 3, 1);
INSERT INTO `user_role` VALUES (2, 1, 5);
INSERT INTO `user_role` VALUES (3, 2, 4);
INSERT INTO `user_role` VALUES (4, 2, 6);

SET FOREIGN_KEY_CHECKS = 1;
