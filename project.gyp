{
	'target_defaults': {
		'defines': [
			'PROJECT_NAME="stack"',
			'PROJECT_VERSION="v0.1-dev"',
			#'PROJECT_BRANCH="<!(hg id -b)"',
			#'PROJECT_REVISION="<!(hg id -i)"',
			#'NDEBUG',
		],
		'cflags': [
			'-Wall',
			'-pipe',
			'-static',
			'-O0',
			'-ggdb',
			'-std=c++11',
			'-pthread',
			'-fPIE',
			'-fPIC',
			'-fno-stack-protector',
			'-m32',
		],
		'ldflags': [
			'-m32',
			'-static',
		],
	},
	'targets': [
		{
			'target_name': 'stack',
			'type': 'executable',
			'dependencies': [
			],
			'include_dirs': [
			],
			'defines': [
			],
			'sources': [
				'src/main.cpp',
			],
			'libraries': [
				'-lpthread',
				'-lboost_system',
				'-lboost_thread',
				'-lboost_filesystem',
				'-lboost_program_options',
			],
		},
	],
}
