import { API } from "../api";
import { UIComponent } from "./ui-components";

export class Collapsible extends UIComponent {
  private title: string;
  private expanded: boolean;
  private contentContainer: any; // LinearLayout for child components
  private arrowView: any; // ImageView for arrow icon

  constructor(id: string, title: string, expanded: boolean = false) {
    super(id);
    this.title = title;
    this.expanded = expanded;
    this.value = expanded; // Use value to store expanded state
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const TextView = API.TextView;
    const ImageView = API.ImageView;
    const Color = API.Color;
    const String = API.JString;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const LinearLayoutParams = API.LinearLayoutParams;
    const View = API.View;

    // Main vertical container
    const container = LinearLayout.$new(context);
    container.setOrientation(1); // VERTICAL
    container.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    container.setBackgroundColor(0xff444444 | 0); // Dark gray background
    container.setPadding(8, 8, 8, 8);

    // Title row (horizontal layout: arrow + text)
    const titleRow = LinearLayout.$new(context);
    titleRow.setOrientation(0); // HORIZONTAL
    titleRow.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    titleRow.setPadding(8, 8, 8, 8);
    titleRow.setBackgroundColor(0xff555555 | 0); // Slightly lighter gray

    // Arrow icon (ImageView)
    this.arrowView = ImageView.$new(context);
    // Create a simple arrow drawable using a triangle shape (for simplicity, we'll use text)
    // Alternatively, we can use a drawable or Unicode arrow characters
    // Using Unicode arrows: ▼ for expanded, ▶ for collapsed
    const arrowText = this.expanded ? "▼" : "▶";
    // For ImageView we need a drawable; let's use TextView for simplicity
    // Replace with proper drawable if needed
    const arrowTextView = TextView.$new(context);
    arrowTextView.setText(String.$new(arrowText));
    arrowTextView.setTextColor(Color.WHITE.value);
    arrowTextView.setTextSize(14);
    arrowTextView.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    this.arrowView = arrowTextView; // Store as arrowView

    // Title text
    const titleView = TextView.$new(context);
    titleView.setText(String.$new(this.title));
    titleView.setTextColor(Color.WHITE.value);
    titleView.setTextSize(16);
    titleView.setTypeface(null, 1); // BOLD
    titleView.setLayoutParams(
      LinearLayoutParams.$new(
        0, // width will be set by weight
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        1.0, // weight
      ),
    );

    titleRow.addView(this.arrowView);
    titleRow.addView(titleView);

    // Content container (initially visible or gone based on expanded state)
    this.contentContainer = LinearLayout.$new(context);
    this.contentContainer.setOrientation(1); // VERTICAL
    this.contentContainer.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    this.contentContainer.setPadding(16, 8, 8, 8);
    if (this.expanded) {
      this.contentContainer.setVisibility(View.VISIBLE.value);
    } else {
      this.contentContainer.setVisibility(View.GONE.value);
    }

    container.addView(titleRow);
    container.addView(this.contentContainer);

    this.view = container;

    // Store references
    (this.view as any).titleRow = titleRow;
    (this.view as any).titleView = titleView;
    (this.view as any).contentContainer = this.contentContainer;

    // Add click listener to title row
    const OnClickListener = API.OnClickListener;
    const self = this;

    const clickListener = Java.registerClass({
      name:
        "com.frida.CollapsibleClickListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnClickListener],
      methods: {
        onClick: function (v: any) {
          self.toggle();
        },
      },
    });
    titleRow.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Collapsible:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    // Update expanded state
    this.expanded = this.value;
    Java.scheduleOnMainThread(() => {
      const View = API.View;
      const String = API.JString;
      const contentContainer = (this.view as any).contentContainer;
      const arrowView = this.arrowView;

      if (contentContainer) {
        if (this.expanded) {
          contentContainer.setVisibility(View.VISIBLE.value);
        } else {
          contentContainer.setVisibility(View.GONE.value);
        }
      }
      if (arrowView) {
        const arrowText = this.expanded ? "▼" : "▶";
        arrowView.setText(String.$new(arrowText));
      }
    });
  }

  /**
   * Toggle expanded/collapsed state
   */
  public toggle(): void {
    this.value = !this.value;
    this.updateView();
    this.emit("toggle", this.value);
  }

  /**
   * Expand the collapsible
   */
  public expand(): void {
    this.value = true;
    this.updateView();
    this.emit("expand");
  }

  /**
   * Collapse the collapsible
   */
  public collapse(): void {
    this.value = false;
    this.updateView();
    this.emit("collapse");
  }

  /**
   * Set title
   */
  public setTitle(title: string): void {
    this.title = title;
    if (!this.view) {
      console.warn(
        `[Collapsible:${this.id}] Cannot set title - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const titleView = (this.view as any).titleView;
      if (titleView) {
        const String = API.JString;
        titleView.setText(String.$new(title));
      }
    });
  }

  /**
   * Add a child view to the content area
   * Note: This adds the view directly to the content container.
   * The child component must already be initialized.
   */
  public addChildView(view: any): void {
    if (!this.contentContainer) {
      console.warn(
        `[Collapsible:${this.id}] Cannot add child - content container not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      this.contentContainer.addView(view);
    });
  }

  /**
   * Remove a child view from the content area
   */
  public removeChildView(view: any): void {
    if (!this.contentContainer) {
      return;
    }
    Java.scheduleOnMainThread(() => {
      try {
        this.contentContainer.removeView(view);
      } catch (error) {
        // Ignore
      }
    });
  }

  /**
   * Clear all child views
   */
  public clearChildren(): void {
    if (!this.contentContainer) {
      return;
    }
    Java.scheduleOnMainThread(() => {
      this.contentContainer.removeAllViews();
    });
  }
}
