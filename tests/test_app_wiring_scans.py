def test_scans_and_auth_routes_registered_in_real_app():
    from backend.api.main import app

    paths = app.openapi()["paths"]
    assert "/scans/" in paths, f"/scans/ missing; have {sorted(paths)}"
    assert "post" in paths["/scans/"]
    assert "/auth/login" in paths
