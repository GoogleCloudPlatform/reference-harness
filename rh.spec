# -*- mode: python ; coding: utf-8 -*-

from PyInstaller.utils.hooks import collect_data_files, collect_all

datas = [('app/skills', 'app/skills'), ('app/app_utils', 'app/app_utils')]
datas += collect_data_files('litellm')

tk_datas, tk_binaries, tk_hiddenimports = collect_all('tiktoken')
ext_datas, ext_binaries, ext_hiddenimports = collect_all('tiktoken_ext')
datas += tk_datas + ext_datas

a = Analysis(
    ['scan.py'],
    pathex=[],
    binaries=tk_binaries + ext_binaries,
    datas=datas,
    hiddenimports=tk_hiddenimports + ext_hiddenimports + [
        'tiktoken_ext.openai_public',
        'tiktoken_ext',
        'google.adk.cli',
        'uvicorn',
        'uvicorn.loops',
        'uvicorn.loops.auto',
        'uvicorn.protocols',
        'uvicorn.protocols.http',
        'uvicorn.protocols.http.auto',
        'uvicorn.protocols.websockets',
        'uvicorn.protocols.websockets.auto',
        'uvicorn.lifespan',
        'uvicorn.lifespan.on',
        'uvicorn.lifespan.off',
        'fastapi',
        'starlette',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='rh',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
