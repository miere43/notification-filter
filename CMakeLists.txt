cmake_minimum_required(VERSION 3.22)

project(
	NotificationFilter
	VERSION 1.1.0
	LANGUAGES CXX
	DESCRIPTION "SKSE plugin that allows hiding notifications based on customizable rules."
)
set(PROJECT_FRIENDLY_NAME "Notification Filter")
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/Plugin.h.in
	${CMAKE_CURRENT_SOURCE_DIR}/src/Plugin.h
	@ONLY
)

configure_file(
	${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.rc.in
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
	@ONLY
)

add_library(
	${PROJECT_NAME}
	SHARED
	src/main.cpp
	src/Plugin.h
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
)

find_package(binary_io CONFIG REQUIRED)
find_package(CommonLibSSE CONFIG REQUIRED)
find_package(xbyak CONFIG REQUIRED)
find_path(SIMPLEINI_INCLUDE_DIRS "ConvertUTF.c")

target_link_libraries(${PROJECT_NAME} PRIVATE CommonLibSSE::CommonLibSSE)
target_link_libraries(${PROJECT_NAME} PRIVATE xbyak::xbyak)
target_include_directories(${PROJECT_NAME} PRIVATE ${SIMPLEINI_INCLUDE_DIRS})
