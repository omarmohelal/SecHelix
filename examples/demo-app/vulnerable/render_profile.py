"""Template rendering: user text is interpolated into markup unescaped."""


def render_profile(display_name, bio):
    # Both values come from the user and reach the document as markup.
    return f"<h1>{display_name}</h1><div class='bio'>{bio}</div>"
